
import inspect
import traceback
import caretaker.config as config
import caretaker.master as master
import ollama
import re
import linecache

DEBUG = True

def ExceptionHandler(description="", output="", unit_tests=True ):
    # what configuration object do we allow
    # I need unit test database

    def decorator(func):
        def wrapper(*args, **kwargs):
            
            if (DEBUG):
                print(f"Wrapper before function {func}")
            try:
                result = func(*args, **kwargs)
            except:
                source_code = inspect.getsource(func)       
                
                if (DEBUG):
                    print(f"Retrieved Source: \n{source_code}")

            return result
        return wrapper
    return decorator