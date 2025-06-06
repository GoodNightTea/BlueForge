# utils/logging.py
import logging
import sys
from datetime import datetime

# Configure the root logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def get_logger(name):
    """Get a logger instance for the given name"""
    logger = logging.getLogger(name)
    
    # Add a console handler if none exists
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    return logger

def set_log_level(level):
    """Set the global log level"""
    if isinstance(level, str):
        level = getattr(logging, level.upper())
    
    logging.getLogger().setLevel(level)
    
    # Update all existing loggers
    for logger_name in logging.Logger.manager.loggerDict:
        logger = logging.getLogger(logger_name)
        logger.setLevel(level)

def enable_debug():
    """Enable debug logging"""
    set_log_level(logging.DEBUG)

def disable_debug():
    """Disable debug logging"""
    set_log_level(logging.INFO)

# Create a default logger for the framework
blueforge_logger = get_logger('blueforge')