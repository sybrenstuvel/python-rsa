import atexit
import json
import logging
import logging.config
import logging.handlers
import logging.handlers
import pathlib
import queue


def run_once(f):
    def wrapper(*args, **kwargs):
        if not wrapper.has_run:
            wrapper.has_run = True
            return f(*args, **kwargs)

    wrapper.has_run = False
    return wrapper


@run_once
def __setup_logging():
    """
    On production stop logging, change logger mode to INFO
    """

    project_root = next(
        p for p in pathlib.Path(__file__).parents if p.parts[-1] == 'python-rsa'
    )

    log_folder = project_root / "logs"
    log_folder.mkdir(exist_ok=True)

    with open(project_root / "rsa/core/config/logger_config.json", "r") as f_in:
        config = json.load(f_in)

    for handler_name, handler in config.get("handlers", {}).items():
        if "filename" in handler:
            handler["filename"] = str(log_folder / pathlib.Path(handler["filename"]).name)

    # Set up logging configuration
    logging.config.dictConfig(config)

    log_queue = queue.Queue(-1)
    queue_handler = logging.handlers.QueueHandler(log_queue)

    # Add QueueHandler to root logger
    root_logger = logging.getLogger()

    # Check if QueueHandler already exists to avoid duplication
    if not any(isinstance(h, logging.handlers.QueueHandler) for h in root_logger.handlers):
        root_logger.addHandler(queue_handler)

    # Set up QueueListener with existing handlers, excluding QueueHandler
    handlers = [h for h in root_logger.handlers if not isinstance(h, logging.handlers.QueueHandler)]
    listener = logging.handlers.QueueListener(log_queue, *handlers, respect_handler_level=True)
    listener.start()

    def cleanup():
        try:
            listener.stop()
        except Exception as e:
            root_logger.error("Error stopping QueueListener: %s", e)
        finally:
            queue_handler.close()
            for handler in root_logger.handlers:
                handler.close()

    atexit.register(cleanup)

    root_logger.debug("logger is configured")


__setup_logging()
