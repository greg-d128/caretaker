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
        return model.execute(prompt)

    def list_models(self):
        return list(self.models.keys())

    def remove_model(self, model_id):
        if model_id not in self.models:
            logger.error(f"Unable to remove a model. Model {model_id} is not present.")
        del self.models[model_id]
        logger.debug(f"Successfully removed model_id {model_id}")


models=Models()


