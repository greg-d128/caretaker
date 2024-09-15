
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
logger = logging.getLogger("prompts")

# New proposal, this will eventually be moved into a configuration
# system. There is a dictionary including insturctions, contexts, etc.
# We can tailor the prompt to the capability of the model (e.g. context size)

instructions = {'exception':"A Python function has encountered an error. Using the information below, please create an alternate version to replace the one that has failed. Pay careful attention to managing errors. \n",
                'output': "A Python function has returned invalid output. Using the information below, please create an alternate version to replace the one that has failed. Pay carefule attention to managing errors. The function that failed was called with the following input: \n\n {fn_input}.\n",
                'missing': "A Python function has been called, but it was unable to be found. This function is missing and will need to be created from scratch. Using any and all information provided (function name, section of calling code), please generate the missing function. \nTraceback:\n {traceback} \n\n Calling Code: {calling_code}\n\n"}

context = {'simple': "You are a caretaker AI of a program. Your job is to make sure the code under your responsibility continues to operate and provide correct results, even if unexpected errors or input happens. While a correct behavior may not always be known, the program should never, ever crash. Do not provide sample code and assume that straight replacement of one function for another will take place. Your task is to fix a python program by replacing the function or code provided with one that fixes the issue. Only the outputted program code matters as it will be injected into running program with the hope of fixing operational issue. This is a big responsibility, please take care in making sure you generate well functioning code.\n" }

constraints = {'simple': "Do not change function names. You can assume that if a function calls other functions, then those functions exist.\n"}

# Part of the prompt that describes errors, if present

errors = {} 

stack = {}

output = {'simple': """The expected output is a python code generated between start_marker and end_marker as below:
          start_marker = ```python\n 
          end_marker = ```
          """}



prompts=[]

prompts.append("""### Problem:
{context}
{instruction}

### Source Code:
{source_code}

### Error Message:
{error_message}

### Task:
Please analyze the source code and the error message. Identify the root cause of the error and suggest a revised version of the function that fixes the issue. Ensure the revised function handles this and other common error conditions gracefully.
Provide the complete fixed function. Do not include sample code. Do not change the name or signature of this function please.

### Response:
""")


def get_prompt(dct, logger=logger):
    """This will needs to be made more intelligent. We are just passing in a dictionary.
    Based on the values in the dict we should select the best prompt."""
    logger.debug(f"get_prompt called with {pprint.pformat(dct)}")
    return prompts[0].format(**dct)