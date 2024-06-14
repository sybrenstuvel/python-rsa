import functools
import logging.handlers
import time
import typing
import rsa.core.config.logger_setup


def log_decorator(logger: logging.Logger):
    def decorator(func: typing.Callable) -> typing.Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger.debug(f"Starting {func.__name__} with args={args}, kwargs={kwargs}")
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                elapsed_time = time.perf_counter() - start_time
                logger.debug(f"Finished {func.__name__} in {elapsed_time:.4f}s with result={result}")
                return result
            except Exception as e:
                logger.exception(f"Error in {func.__name__} with args={args}, kwargs={kwargs}: {e}")
                raise

        return wrapper

    return decorator
