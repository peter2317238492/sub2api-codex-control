from fastapi import APIRouter, WebSocket

router = APIRouter()


@router.websocket("/codex-ws/device")
@router.websocket("/ws/device")
async def device_websocket(websocket: WebSocket) -> None:
    await websocket.app.state.realtime.handle_device(websocket)


@router.websocket("/codex-ws/browser")
@router.websocket("/ws/browser")
async def browser_websocket(websocket: WebSocket) -> None:
    await websocket.app.state.realtime.handle_browser(websocket)
