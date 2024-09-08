
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
        def fix_code(orig_source, error_text, env): 

            # number of attempts before we give up.
            for x in range(10):           
                new_source = ai.models.fixCode(orig_source, error_text)
                # Try to compile it?
                new_fn = eval(new_source, env)



        def wrapper(*args, **kwargs):
            
            logger.debug(f"Wrapper before function {func}")
            try:
                result = func(*args, **kwargs)
            except:
                logger.debug(f"Decorator caught exception")
                source_code = inspect.getsource(func)       
                logger.debug(f"Retrieved Source: \n{source_code}")
                new_fn = fix_code(source_code, error_text, env)
                # try to call it and see what happens
                #new_fn = eval(new_code)
                # verify that this will actually do what I want.
                func = new_fn
                
            return result
        return wrapper
    return decorator


def AssertVerifier(description="", output="", unit_tests=True ):
    """Decorator that will verify that return is within appropriate range.
    If return is not within range, fix an run again.
    This will allow an empty string return to trigger a rewrite.
    """
    pass


def LogVerifier():
    """Can my decorator access logs from this one function and verify that things are 
    going well?"""
    pass

