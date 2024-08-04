import inspect
import traceback
import caretaker.config as config
import re
import linecache

from huggingface_hub import hf_hub_download
from llama_cpp import Llama


DEBUG = False

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

    #model_name = "Crataco/stablelm-2-1_6b-chat-imatrix-GGUF"
    #model_file = "stablelm-2-1_6b-chat.Q5_K_M.imx.gguf"
    print("To delete LLM models from hugging-face client use:\n   'huggingface-cli delete-cache'")
    onward = input("Downloading 3.4GB LLM model. Continue? (y/n) ")
    if onward.lower()!="y" and onward.lower()!="yes":
        exit()

    model_name = "TheBloke/deepseek-coder-1.3b-instruct-GGUF"
    model_file = "deepseek-coder-1.3b-instruct.Q4_K_M.gguf" # ~3.4GB

    ## Download the model
    model_path = hf_hub_download(model_name, filename=model_file)
    model_kwargs = {
        "n_ctx":4096,    # Context length to use
        "n_threads":4,   # Number of CPU threads to use
        "n_gpu_layers":0,# Number of model layers to offload to GPU. Set to 0 if only using CPU
    }

    ## Instantiate model from downloaded file
    llm = Llama(model_path=model_path, **model_kwargs)

    ## Generation kwargs
    textgen_kwargs = {
        "max_tokens":200, # Max number of new tokens to generate
        "stop":["<|endoftext|>", "</s>", "<|user|>", "<|assistant|>", "<|end|>", "---"],#, "Say:"], # Text sequences to stop generation on
        "echo":False, # Echo the prompt in the output
        "top_k":3 # This is essentially greedy decoding, since the model will always return the highest-probability token. Set this value > 1 for sampling decoding
    }

    #DEBUG:
    input("PROMPT: "+prompt)

    res = llm(prompt, **textgen_kwargs) # Res is a dictionary
    output = res["choices"][0]["text"]

    #DEBUG:
    input("OUTPUT: "+output)

    #prompt = config.prompt.format(source_code=orig_source_code, error_message=err_text)
    #response = ollama.chat(model=config.model, messages=[
    #{
    #    'role':'user',
    #    'content':prompt,
    #}, ])
    #output = response['message']['content']

    start_marker="```python\n"
    end_marker = "```"
    pattern = re.compile(f'{start_marker}(.*?){end_marker}', re.DOTALL)
    matches = pattern.findall(output)
    if matches:
        corrected = matches[0]
        #DEBUG:
        input("CORRECTED!")
        return corrected
    else:
        # Possibly try again with a fallback LLM? 
        # We do not have to give up
        #DEBUG:
        input("FAIL!")
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