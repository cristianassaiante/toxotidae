from __future__ import annotations
import logging


class Logger:
    level = logging.INFO
    instance = None

    @staticmethod
    def log() -> logging.Logger:
        if Logger.instance:
            return Logger.instance
        Logger.instance = Logger.__get_logger(Logger.level)
        return Logger.instance

    @staticmethod
    def set_debug() -> None:
        Logger.level = logging.DEBUG

    @staticmethod
    def is_debug() -> bool:
        return Logger.level == logging.DEBUG

    @staticmethod
    def __get_logger(level: int) -> logging.Logger:
        logger = logging.getLogger(__name__)
        logger.setLevel(Logger.level)
        handler = logging.StreamHandler()
        handler.setLevel(Logger.level)
        formatter = logging.Formatter(
            "[{asctime}] {message}", "%Y-%m-%d %H:%M:%S", style="{"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
