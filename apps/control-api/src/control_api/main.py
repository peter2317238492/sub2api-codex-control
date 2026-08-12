from .app import create_app
from .logging_config import configure_json_logging

configure_json_logging()
app = create_app()
