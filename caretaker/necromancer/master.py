
import caretaker.config as config
import caretaker.prompts as prompts
import caretaker.ai as ai
import caretaker.decorators.decorators.ExceptionHandler as ExceptionHandler
import inspect
import traceback
import re
import linecache
import pprint
import logging
import sys

logger = logging.getLogger("necromancer")

def retrieve_fn_code(frames, frame, logger=logger):
    """Retrieves the source code of the function on the the stack.
    Starts at lowest level and returns code of first function it finds 
    of the same name. Returns empty sting if not found."""
    
    function_name = frames[-1][2]

    logger.debug(f"retrieve_fn_code - function_name = {function_name}")
    function = None
    for filename, line_number, function_name, _ in reversed(frames):
        if function_name in frame.f_globals.keys():
            function = frame.f_globals[function_name]
            break
    if function:
        source_code = inspect.getsource(function)
        logger.debug(f"retrieve_fn_code - source_code \n====\n{source_code}\n====\n\n")
    else:
        logger.warning(f"retrieve_fn_code - source_code is empty\n\n")
        source_code = ''

    logger.debug("retrieve_fn_code, returning")

    return source_code

def continueExec(frame, f_globals, f_locals, logger=logger):
            
    # Now re-run the code that failed
    # This function should be made aware of the stack
    # So that when function is completed, it can go up the stack and continue
    code_context = frame.f_code
    lineno = frame.f_lineno
    
    lines = linecache.getlines(code_context.co_filename)

    for i in range(lineno -1 , len(lines)):
        exec(lines[i], f_globals, f_locals)
    logger.debug("continueExec - Should go up the stack here and continue")

@ExceptionHandler
def exc(exc_type, exc_value, exc_tb, logger=logger):
    "Global exception hook"
    logger.debug(f"exc - Global Exception Hook")

    # obtain environment information about our exception
    stack = inspect.stack()
    frames = traceback.extract_tb(exc_tb)
    frame = exc_tb.tb_frame

    source_code = retrieve_fn_code(frames, frame)
        
    corrected = ai.models.fixCode(source_code, exc_value)
    
    # Inject code
    if corrected:
        # Retrieve the environment in which this original function existed
        f_locals = exc_tb.tb_frame.f_locals
        f_globals = exc_tb.tb_frame.f_globals
        # Execute the new function definition within this environment
        logger.debug(f"exc - Injecting new code\n\n")
        exec(corrected, f_globals, f_locals)

        # Continue execution 
        continueExec(frame,f_globals, f_locals)


def activate_necromancer():
    sys.excepthook = exc

if "necromancer" in config.activate:
    activate_necromancer()     