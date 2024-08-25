
# Right now we are going to just have multiple prompts available.
# Choose one, pass in the values and hope we get an answer.

# In the future need a system of, hopefully selecting the appropriate prompt
# for each model. 

import logging
import pprint
logger = logging.getLogger("prompts")

prompts=[]

prompts.append("""### Problem:
A Python function has encountered an error. Below is the source code of the function and the error message generated.

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