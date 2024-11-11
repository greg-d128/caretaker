
import inspect
import traceback
import caretaker.config as config
from caretaker.ai import ai
import caretaker.prompts as prompts
import linecache
import logging
import functools

logger = logging.getLogger("decorators")

# In order to generate a prompt 

# Convenience Function. These can pull information into standard dictionaries
# 




def ExceptionHandler(func):
    
    def fix_code(prompt):
        logger.debug("Fixing code")
        
        new_code = ai.getCode(prompt)
        logger.debug(f"Fixed Code {new_code}")
        return None
    
    def wrapper(*args, **kwargs):
        logger.debug(f"Wrapper before function {func.__name__}")
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.debug(f"Decorator caught exception")
            dct={
                'task' : 'exception',
                'fn_name': func.__name__,
                'fn_input': {'args': args, 'kwargs': kwargs},
                # 'fn_output': No output since we have an exception
                'traceback': traceback.format_tb(e.__traceback__),
                'calling_code' : inspect.getsource(func),
                'error_message' : str(e),
                # 'log_output': Do not have this yet
            }
     
            logger.debug(f"Retrieved Source Dictionary: \n{dct}")
            prompt = prompts.generate_prompt(dct)
            logger.debug(f"Generated a prompt:\n\n {prompt}\n\n")
            new_source = fix_code(prompt)
            logger.debug(f"Retrieved Source: \n{prompt}")
            
            # fix_code(sourc)
            #new_fn = fix_code(source_code, error_text, env)
            return None


    return wrapper





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

