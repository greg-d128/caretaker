import inspect
import traceback
import caretaker.config as config
import ollama
import re
import linecache

DEBUG = True

def retrieve_fn_code(frames, frame):
    """Retrieves the source code of the function on the the stack.
    Starts at lowest level and returns code of first function it finds 
    of the same name. Returns empty sting if not found."""
    

    function_name = frames[-1][2]

    function = None
    for filename, line_number, function_name, _ in reversed(frames):
        if function_name in frame.f_globals.keys():
            function = frame.f_globals[function_name]
            break
    if function:
        source_code = inspect.getsource(function)
    else:
        source_code = ''

    return source_code


def fix_function(orig_source_code, err_text):
    "Generates a new version of the function."
    prompt = config.prompt.format(source_code=orig_source_code, error_message=err_text)
    response = ollama.chat(model=config.model, messages=[
    {
        'role':'user',
        'content':prompt,
    }, ])

    output = response['message']['content']
    start_marker="```python\n"
    end_marker = "```"
    pattern = re.compile(f'{start_marker}(.*?){end_marker}', re.DOTALL)
    matches = pattern.findall(output)
    if matches:
        corrected = matches[0]
        return corrected
    else:
        # Possibly try again with a fallback LLM? 
        # We do not have to give up
        return ''
    
def continueExec(frame, f_globals, f_locals):
            
    # Now re-run the code that failed
    code_context = frame.f_code
    lineno = frame.f_lineno
    
    lines = linecache.getlines(code_context.co_filename)

    for i in range(lineno -1 , len(lines)):
        exec(lines[i], f_globals, f_locals)


def exc(exc_type, exc_value, exc_tb):
    "Global exception hook"
    # obtain environment information about our exception
    stack = inspect.stack()
    frames = traceback.extract_tb(exc_tb)
    frame = exc_tb.tb_frame

    source_code = retrieve_fn_code(frames, frame)
    if DEBUG:
        print("Catching exception")
        print(f"{source_code} {exc_value}")
    
    corrected = fix_function(source_code, exc_value)
    
    # Inject code
    if corrected:
        # Retrieve the environment in which this original function existed
        f_locals = exc_tb.tb_frame.f_locals
        f_globals = exc_tb.tb_frame.f_globals
        # Execute the new function definition within this environment
        exec(corrected, f_globals, f_locals)

        # Continue execution (kinda)
        continueExec(frame,f_globals, f_locals)