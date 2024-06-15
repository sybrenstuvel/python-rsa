import atexit
import json
import logging
import logging.config
import logging.handlers
import pathlib
import queue
from typing import Any, Dict, Callable

logger = logging.getLogger(__name__)


def run_once(f) -> Callable:
    def wrapper(*args, **kwargs):
        if not wrapper.has_run:
            wrapper.has_run = True
            return f(*args, **kwargs)

    wrapper.has_run = False
    return wrapper


class LoggingConfigurator:
    def __init__(self, project_root: pathlib.Path) -> None:
        self.project_root = project_root
        self.log_folder = self.create_log_folder()
        self.config = self.load_logging_config()
        self.update_handler_paths()
        logging.config.dictConfig(self.config)
        logger.debug("Logger configuration loaded and applied.")

    def create_log_folder(self) -> pathlib.Path:
        """Ensure the log folder exists."""
        log_folder = self.project_root / "logs"
        log_folder.mkdir(exist_ok=True)
        return log_folder

    def load_logging_config(self) -> Dict[str, Any]:
        """Load logging configuration from JSON file."""
        config_path = self.project_root / "rsa/core/config/logger_config.json"
        with open(config_path, "r") as f_in:
            config = json.load(f_in)
        return config

    def update_handler_paths(self) -> None:
        """Update file paths in logging configuration."""
        for handler in self.config.get("handlers", {}).values():
            if "filename" in handler:
                handler["filename"] = str(self.log_folder / pathlib.Path(handler["filename"]).name)


class LoggingSetup:
    def __init__(self, configurator: LoggingConfigurator) -> None:
        self.configurator = configurator
        self.log_queue = queue.Queue(-1)
        self.queue_handler = self.setup_queue_handler()
        self.listener = self.setup_queue_listener()
        self.register_cleanup()
        logger.debug("Logger is configured")

    def setup_queue_handler(self) -> logging.handlers.QueueHandler:
        """Set up QueueHandler for asynchronous logging."""
        queue_handler = logging.handlers.QueueHandler(self.log_queue)
        if not any(isinstance(h, logging.handlers.QueueHandler) for h in logger.handlers):
            logger.addHandler(queue_handler)
        return queue_handler

    def setup_queue_listener(self) -> logging.handlers.QueueListener:
        """Set up QueueListener with existing handlers, excluding QueueHandler."""
        handlers = [h for h in logger.handlers if not isinstance(h, logging.handlers.QueueHandler)]
        listener = logging.handlers.QueueListener(self.log_queue, *handlers, respect_handler_level=True)
        listener.start()
        return listener

    def register_cleanup(self) -> None:
        """Register cleanup function to stop listener and close handlers."""

        def cleanup() -> None:
            try:
                self.listener.stop()
            except Exception as e:
                logger.error("Error stopping QueueListener: %s", e)
            finally:
                self.queue_handler.close()
                for handler in logger.handlers:
                    handler.close()

        atexit.register(cleanup)


@run_once
def setup_logging() -> None:
    """Set up logging configuration. On production, change logger mode to INFO."""
    project_root = next(p for p in pathlib.Path(__file__).parents if p.parts[-1] == 'python-rsa')
    LoggingSetup(LoggingConfigurator(project_root))

