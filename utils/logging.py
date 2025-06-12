
# utils/logging.py - Logging Configuration and Management
import logging
import logging.handlers
import sys
import os
from pathlib import Path
from typing import Optional
from datetime import datetime

# Global logger registry
_loggers = {}

def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """Get or create a logger with the specified name"""
    
    if name in _loggers:
        return _loggers[name]
    
    # Create logger
    logger = logging.getLogger(name)
    
    # Prevent duplicate handlers
    if logger.handlers:
        _loggers[name] = logger
        return logger
    
    # Set log level
    if level:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    else:
        logger.setLevel(logging.INFO)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.WARNING)  # Only warnings and above to console
    console_handler.setFormatter(simple_formatter)
    
    # File handler (if logs directory exists)
    logs_dir = Path("logs")
    if logs_dir.exists() or _create_logs_directory():
        file_handler = logging.handlers.RotatingFileHandler(
            logs_dir / "blueforge.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
    
    # Add console handler
    logger.addHandler(console_handler)
    
    # Store in registry
    _loggers[name] = logger
    
    return logger

def _create_logs_directory() -> bool:
    """Create logs directory if it doesn't exist"""
    try:
        Path("logs").mkdir(exist_ok=True)
        return True
    except Exception:
        return False

def setup_logging(level: str = "INFO", 
                 log_file: Optional[str] = None,
                 console_level: str = "WARNING") -> None:
    """Setup global logging configuration"""
    
    # Create logs directory
    _create_logs_directory()
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, console_level.upper(), logging.WARNING))
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_path = Path("logs") / log_file
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = Path("logs") / f"blueforge_{timestamp}.log"
    
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=50*1024*1024,  # 50MB
            backupCount=10
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not setup file logging: {e}")

def set_log_level(logger_name: str, level: str) -> None:
    """Set log level for a specific logger"""
    logger = logging.getLogger(logger_name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

def get_log_level(logger_name: str) -> str:
    """Get current log level for a logger"""
    logger = logging.getLogger(logger_name)
    return logging.getLevelName(logger.level)

def log_function_call(func):
    """Decorator to log function calls"""
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"{func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"{func.__name__} failed with error: {e}")
            raise
    return wrapper

def log_async_function_call(func):
    """Decorator to log async function calls"""
    async def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        logger.debug(f"Calling async {func.__name__} with args={args}, kwargs={kwargs}")
        try:
            result = await func(*args, **kwargs)
            logger.debug(f"Async {func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"Async {func.__name__} failed with error: {e}")
            raise
    return wrapper

class BlueForgeLogFilter(logging.Filter):
    """Custom log filter for BlueForge"""
    
    def filter(self, record):
        # Filter out noisy Bleak logs in production
        if record.name.startswith('bleak') and record.levelno < logging.WARNING:
            return False
        
        # Filter out other noisy third-party logs
        noisy_loggers = ['asyncio', 'concurrent.futures']
        if any(record.name.startswith(name) for name in noisy_loggers):
            if record.levelno < logging.ERROR:
                return False
        
        return True

def setup_production_logging():
    """Setup logging configuration optimized for production use"""
    
    # Create logs directory
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()
    
    # Add filter to reduce noise
    log_filter = BlueForgeLogFilter()
    
    # Console handler - only errors and critical
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.ERROR)
    console_handler.addFilter(log_filter)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    ))
    root_logger.addHandler(console_handler)
    
    # Main application log
    app_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "blueforge.log",
        maxBytes=25*1024*1024,  # 25MB
        backupCount=5
    )
    app_handler.setLevel(logging.INFO)
    app_handler.addFilter(log_filter)
    app_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    root_logger.addHandler(app_handler)
    
    # Security events log
    security_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "security.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=10
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(logging.Formatter(
        '%(asctime)s - SECURITY - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Add security handler to security-related loggers
    security_loggers = [
        'security.vurnerability_scanner',
        'exploits.memory_corruption',
        'exploits.protocol_attacks', 
        'exploits.timing_attacks'
    ]
    
    for logger_name in security_loggers:
        security_logger = logging.getLogger(logger_name)
        security_logger.addHandler(security_handler)

def setup_debug_logging():
    """Setup detailed logging for debugging"""
    
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Setup root logger for debug
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()
    
    # Console handler - show more in debug mode
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    ))
    root_logger.addHandler(console_handler)
    
    # Debug file handler
    debug_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "debug.log",
        maxBytes=100*1024*1024,  # 100MB
        backupCount=3
    )
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    root_logger.addHandler(debug_handler)

def create_session_logger(session_id: str) -> logging.Logger:
    """Create a logger for a specific session"""
    
    logger_name = f"session.{session_id}"
    session_logger = get_logger(logger_name)
    
    # Create session-specific log file
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    session_file = logs_dir / f"session_{session_id}.log"
    
    try:
        session_handler = logging.FileHandler(session_file)
        session_handler.setLevel(logging.DEBUG)
        session_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        session_logger.addHandler(session_handler)
    except Exception as e:
        print(f"Warning: Could not create session log file: {e}")
    
    return session_logger

# Initialize default logging on import
if not _loggers:
    # Only setup basic logging if not already configured
    if not logging.getLogger().handlers:
        basic_handler = logging.StreamHandler(sys.stdout)
        basic_handler.setLevel(logging.WARNING)
        basic_handler.setFormatter(logging.Formatter(
            '%(levelname)s - %(message)s'
        ))
        logging.getLogger().addHandler(basic_handler)
        logging.getLogger().setLevel(logging.INFO)