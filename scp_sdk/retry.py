"""
Retry configuration and utilities for the SCP SDK.
"""

import time
import random
from typing import Callable, Any, Optional, List, Type
from functools import wraps
import logging

from .exceptions import SCPError, SCPConnectionError, SCPTimeoutError


class RetryConfig:
    """Configuration for retry behavior."""
    
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        retryable_exceptions: Optional[List[Type[Exception]]] = None
    ):
        """
        Initialize retry configuration.
        
        Args:
            max_attempts: Maximum number of retry attempts
            base_delay: Base delay between retries in seconds
            max_delay: Maximum delay between retries in seconds
            exponential_base: Base for exponential backoff
            jitter: Whether to add random jitter to delays
            retryable_exceptions: List of exception types that should trigger retries
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
        self.retryable_exceptions = retryable_exceptions or [
            SCPConnectionError,
            SCPTimeoutError,
            ConnectionError,
            TimeoutError
        ]
        
        self.logger = logging.getLogger(__name__)
    
    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for a given attempt number.
        
        Args:
            attempt: Current attempt number (0-based)
            
        Returns:
            Delay in seconds
        """
        delay = self.base_delay * (self.exponential_base ** attempt)
        delay = min(delay, self.max_delay)
        
        if self.jitter:
            # Add random jitter (±25% of delay)
            jitter_amount = delay * 0.25
            delay += random.uniform(-jitter_amount, jitter_amount)
            delay = max(0, delay)  # Ensure non-negative
        
        return delay
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """
        Determine if an exception should trigger a retry.
        
        Args:
            exception: Exception that occurred
            attempt: Current attempt number (0-based)
            
        Returns:
            True if should retry, False otherwise
        """
        if attempt >= self.max_attempts - 1:
            return False
        
        return any(isinstance(exception, exc_type) for exc_type in self.retryable_exceptions)


def with_retry(retry_config: RetryConfig = None):
    """
    Decorator to add retry behavior to functions.
    
    Args:
        retry_config: Retry configuration to use
        
    Returns:
        Decorated function with retry behavior
    """
    if retry_config is None:
        retry_config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(retry_config.max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if not retry_config.should_retry(e, attempt):
                        raise
                    
                    if attempt < retry_config.max_attempts - 1:
                        delay = retry_config.calculate_delay(attempt)
                        retry_config.logger.debug(
                            f"Attempt {attempt + 1} failed with {type(e).__name__}: {e}. "
                            f"Retrying in {delay:.2f} seconds..."
                        )
                        time.sleep(delay)
            
            # If we get here, all retries failed
            raise last_exception
        
        return wrapper
    return decorator