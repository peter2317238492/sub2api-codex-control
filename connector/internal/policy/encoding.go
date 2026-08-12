package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	MaxEnsureASCIIParamsBytes    = 224 << 10
	MaxEnsureASCIIProjectedBytes = 224 << 10
	MaxEnsureASCIITextBytes      = 200_000
)

// ensureASCIIJSONSize matches compact Python json.dumps(..., ensure_ascii=True)
// for the string-heavy protocol values. Numeric spelling differences are
// covered by the protocol's 32 KiB envelope reserve.
func ensureASCIIJSONSize(value any) (int, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return 0, err
	}
	decoder := json.NewDecoder(bytes.NewReader(buffer.Bytes()))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return 0, err
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		return 0, errors.New("JSON contains trailing data")
	} else if !errors.Is(err, io.EOF) {
		return 0, err
	}
	buffer.Reset()
	encoder = json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return 0, err
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	size := 0
	for index := 0; index < len(encoded); {
		if encoded[index] < utf8.RuneSelf {
			if encoded[index] == 0x7f {
				size += 6
			} else {
				size++
			}
			index++
			continue
		}
		character, width := utf8.DecodeRune(encoded[index:])
		if character <= 0xffff {
			size += 6
		} else {
			size += 12
		}
		index += width
	}
	return size, nil
}

func ensureASCIIStringContentSize(value string) int {
	size := 0
	for _, character := range value {
		switch {
		case character == '"' || character == '\\':
			size += 2
		case character == '\b' || character == '\f' || character == '\n' || character == '\r' || character == '\t':
			size += 2
		case character < 0x20:
			size += 6
		case character <= 0x7e:
			size++
		case character <= 0xffff:
			size += 6
		default:
			size += 12
		}
	}
	return size
}

// wireJSONStringContentSize is the larger of Python ensure_ascii encoding and
// Go encoding/json encoding for each rune. Go additionally escapes <, >, and &.
func wireJSONStringContentSize(value string) int {
	size := 0
	for _, character := range value {
		size += wireJSONRuneSize(character)
	}
	return size
}

func wireJSONRuneSize(character rune) int {
	switch {
	case character == '"' || character == '\\':
		return 2
	case character == '\b' || character == '\f' || character == '\n' || character == '\r' || character == '\t':
		return 2
	case character < 0x20 || character == 0x7f || character == '<' || character == '>' || character == '&':
		return 6
	case character <= 0x7f:
		return 1
	case character <= 0xffff:
		return 6
	default:
		return 12
	}
}

func truncateWireString(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	used := 0
	end := 0
	for index, character := range value {
		width := wireJSONRuneSize(character)
		if used+width > maximum {
			return value[:end]
		}
		used += width
		_, encodedWidth := utf8.DecodeRuneInString(value[index:])
		end = index + encodedWidth
	}
	return value
}

func projectedJSONWithinBudget(value any) (bool, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	ensureASCIISize, err := ensureASCIIJSONSize(value)
	if err != nil {
		return false, err
	}
	return len(encoded) <= MaxEnsureASCIIProjectedBytes && ensureASCIISize <= MaxEnsureASCIIProjectedBytes, nil
}
