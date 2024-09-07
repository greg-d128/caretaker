
import inspect
import traceback
import caretaker.config as config
import caretaker.ai as ai
import linecache
import logging

logger = logging.getLogger("decorators")



def ExceptionHandler(description="", output="", unit_tests=True ):
    # what configuration object do we allow
    # I need unit test database

    def decorator(func):
        def wrapper(*args, **kwargs):
            
            logger.debug(f"Wrapper before function {func}")
            try:
                result = func(*args, **kwargs)
            except:
                source_code = inspect.getsource(func)       
                logger.debug(f"Retrieved Source: \n{source_code}")

            return result
        return wrapper
    return decorator