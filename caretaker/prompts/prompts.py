
# Right now we are going to just have multiple prompts available.
# Choose one, pass in the values and hope we get an answer.

# In the future need a system of, hopefully selecting the appropriate prompt
# for each model. 

# Thinking logically:
# Each prompt is likely to have following components. Which components 
# get added to a prompt can be dependent on parameters? Context length, etc?
# 1. Instruction
# 2. Context
# 3. Constraints (list of requirements, formatting rules, etc.)
# 4. Examples
# 5. Expected output format. 
# 6. Tone and style
# 

import logging
import pprint
import string
logger = logging.getLogger("prompts")

# New proposal, this will eventually be moved into a configuration
# system. There is a dictionary including insturctions, contexts, etc.
# We can tailor the prompt to the capability of the model (e.g. context size)

# API. The following variables can be passed to the prompt function. 
# Based on the variables available, the prompt will be assembled.

# Processing rules:
# If a task is provided and avaialble in the list - use that list
# Process list in order. Stop the moment all variables are avaialble, fill 
# them out and return text of that section.


# task = What task are we trying to perform?
# fn_name = name of the function that was called
# fn_input = name and values of he input parameters
# fn_output = output of the function 
# traceback = output of traceback stack
# calling_code = function or section of the function that was calling the function that failed
# error_message = The error message
# log_output = Sequence of log messages (future)
# 

class Prompt:
    def __init__(self, prompt=""):
        self.prompt = prompt
        formatter = string.Formatter()
        fields = [field_name for _, field_name, _, _ in formatter.parse(prompt) if field_name]
        self.variables = fields


# instruction - type followed by list of variables used in this section of the prompt

instructions = {
    'exception': [
        Prompt("A Python function named {fn_name} has encountered an error. Using the information below, please create an alternate version to replace the one that has failed. Pay careful attention to managing errors. \n")
        ],
    'output' : [
        Prompt("A Python function named {fn_name} has returned invalid output. This function was called with with these input values: {fn_input}\n. Using the information below, please create an alternate version to replace the one that has failed. Pay carefule attention to managing errors. The function that failed returned the following, incorrect output {fn_output}. \n\n {fn_input}.\n")
    ],    
    'missing' : [
        Prompt("A Python function has been called, but it was unable to be found. This function is missing and will need to be created from scratch. Using any and all information provided (function name, section of calling code), please generate the missing function. \nTraceback:\n {traceback} \n\n Calling Code: {calling_code}\n")
    ],         
    'timing' : [
        Prompt("A Python function has taken an exceptional amount of time to execute. Likely it has been paused while waiting for a timeout, or it was delayed for another reason. Please assist by generating a new version that can handle this situation better.\n")
    ],
    '' : [
        Prompt("There was an unknown problem with the application under your care. Please use any and all information provided to create a python code that will replace this module that is capable of avoiding this error.\n")
    ]                 
                 
                 }

contexts = {
    '': [
        Prompt("You are a caretaker AI of a program. Your job is to make sure the code under your responsibility continues to operate and provide correct results, even if unexpected errors or input happens. While a correct behavior may not always be known, the program should never, ever crash. Do not provide sample code and assume that straight replacement of one function for another will take place. Your task is to fix a python program by replacing the function or code provided with one that fixes the issue. Only the outputted program code matters as it will be injected into running program with the hope of fixing operational issue. This is a big responsibility, please take care in making sure you generate well functioning code.\n")
    ] }

constraints = {
    '' : [
        Prompt("Do not change function names. You can assume that if a function calls other functions, then those functions exist.\n")
    ]
}

errors = {
    '':[
        Prompt("The code above has failed with the following error:\n{error_message}\n"),
        Prompt("Unfortunately no error message is available. Can you still attempt to identify and fix what went wrong?")
    ]
}

stacks = {
    '':[
        Prompt("The following stack trace was generated as part of the error.\n{traceback}\n"),
        Prompt("Unfortunately traceback stack was unable to be collected. Can you do your best in creating a replacement code that addressses the issue based on information provided?\n")
    ]
}

outputs = {
    '' : [
        Prompt("""The expected output is a python code generated between start_marker and end_marker as below:
          start_marker = ```python\n 
          end_marker = ```
          """)
    ]
}


prompts=[]

prompts.append("""### Problem:
{context}

### Errors:
{stack}                    
{error}
               
### Task:
{instruction}
{constraints}
{output}
               
### Response:
""")

def get_instruction(dct, logger=logger):
    task = dct.get("task", "")

    lst = instructions.get(task, instructions[""])
    # we have a list of prompts to process in order

    instruction = None

    for p in lst:
        # check if all variables are present 
        if ( all(var in dct for var in p.variables)):
            instruction = p.prompt.format(dct)

    if not instruction:
        logger.error("This instruction should not ever be taken. Debugging only.")
        instruction = "This instruction should not ever be taken. Debugging only."

    return instruction



def get_stacks(dct, logger=logger):
    "This would be better as a list."
    pass    



def generate_prompt(dct, logger=logger):
    """This is the more intelligent version. 
    A prompt needs to be assembled depending on what information is available."""

    instruction = get_instruction(dct)
    context = contexts.get("","")
    stack = get_stacks(dct)
    error = get_errors(dct)
    output = get_outputs(dct)

    prompt = prompts[0].format(locals())
    logger.debug(f"generate_prompt called with {pprint.pformat(dct)}")
    logger.debug(f"generate_prompt generated output {prompt}")


def get_prompt(dct, logger=logger):
    """This will needs to be made more intelligent. We are just passing in a dictionary.
    Based on the values in the dict we should select the best prompt."""
    logger.debug(f"get_prompt called with {pprint.pformat(dct)}")
    return prompts[0].format(**dct)

