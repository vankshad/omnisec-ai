"""Logging configuration."""

import logging
import sys
from pathlib import Path


def setup_logger(level: str = "INFO", log_file: str = None) -> logging.Logger:
    """Configure logging for OmniSec."""
    logger = logging.getLogger("omnisec")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter(
        "%(asctime)s │ %(levelname)-7s │ %(name)s │ %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(console)

    # File handler
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        ))
        logger.addHandler(fh)

    return logger
