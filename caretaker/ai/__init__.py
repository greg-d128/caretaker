# Abstraction module for AI.
# The basic idea is that this code will attemp to connect to 
# known ai modules. We cannot assume that modules are actually 
# available until we try to run them.

# This represents a common API used inside this code.
# 
# list_models() - list downloaded and available models
# rewrite_code(model, question)
# available() # models available for download
# download

## Lets start with functionality we need.
import logging
import caretaker.ai.ollama as module_ollama
import caretaker.config as config
import caretaker.prompts as prompts
import pprint
import re

module_lst=[module_ollama]

logger = logging.getLogger("ai")


class Models:
    def __init__(self):
        self.models = {}

    def register_model(self, model_id, model_function):
        logger.debug(f"Registering model: {model_id}")
        self.models[model_id] = model_function

    def get_model(self, model_id):

        ret = self.models.get(model_id, None)
        if ret:
            logger.debug(f"Successfully retrieved model_id: {model_id}")
        else:
            logger.debug(f"Unable to retrieve model_id {model_id}")
        
        return ret
    
    def execute_prompt(self, model_id, prompt):
        logger.debug(f"Executing prompt on model {model_id}\n{prompt}\n\n")
        model = self.get_model(model_id)
        if not model:
            raise ValueError(f"Model with ID {model_id} not found.")
        return model(prompt)

    def list_models(self):
        return list(self.models.keys())

    def remove_model(self, model_id):
        if model_id not in self.models:
            logger.error(f"Unable to remove a model. Model {model_id} is not present.")
        del self.models[model_id]
        logger.debug(f"Successfully removed model_id {model_id}")

    def fixCode(self, orig_code, error_text):
        "This will return fixed code, if possible."

        request_dct = {"source_code":orig_code, "error_message":error_text }
        logger.warning(f"fix_function - {pprint.pformat(request_dct)}")
        
        # Get a better handle on prompts.
        prompt = prompts.get_prompt(request_dct)
        
        logger.debug(f"fix_function - using prompt:\n====\n{prompt}\n====\n\n")
        
        # TBI Change to dynamically adapt to what is available.
        # config?
        response = self.models.execute_prompt(config.model_preference[0], prompt)

        logger.debug(f"fix_function, LLM response object\n\n====\n{pprint.pformat(response)}\n====\n\n")

        output = response['message']['content']
        start_marker="```python\n"
        end_marker = "```"
        pattern = re.compile(f'{start_marker}(.*?){end_marker}', re.DOTALL)
        matches = pattern.findall(output)
        if matches:
            corrected = matches[0]
            logging.debug(f"fix_function - Corrected function\n====\n{corrected}\n====\n\n")
            return corrected
        else:
            # Possibly try again with a fallback LLM? 
            # We do not have to give up
            logging.warning("fix_function - unable to parse out a replacement function")
            return ''        



models=Models()


for m in module_lst:
    m.init(models)

