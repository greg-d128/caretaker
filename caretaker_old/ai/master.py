# ai.py

import logging
from caretaker.ai.model import Model
import code

# Set up logger
logger = logging.getLogger("ai") 

class AI:
    def __init__(self, models=[], client=None):
        """
        Initializes the AI instance with a list of models.

        Args:
            models (list, optional): A list of Model instances.
        """
        self.models = [Model(x, client=client) for x in models if models ]
        self.client=client
        logger.info(f"AI initialized with models: {[model.get('name') for model in self.models]}")

    def update(self, models):
        """
        Updates the models in the AI instance.

        Args:
            models (list): A list of Model instances to update or add.
        """
        
        for new_model in models:
            # Check if a model with the same name exists
            existing_model = next(
                (model for model in self.models if model.get('name') == new_model.get('name')),
                None
            )
            if existing_model:
                # Update existing model's information
                index = self.models.index(existing_model)
                self.models[index] = new_model
                logger.info(f"Updated model '{new_model.get('name')}'")
            else:
                # Add new model to the list
                self.models.append(new_model)
                logger.info(f"Added new model '{new_model.get('name')}'")

    def select_best_models(self, exclude_models=None):
        """
        Selects the models in order of their scores.

        Args:
            exclude_models (list, optional): A list of models to exclude from selection.

        Returns:
            list: A list of models ordered by their scores, from highest to lowest.
        """
        if exclude_models is None:
            exclude_models = []

        available_models = [model for model in self.models if model not in exclude_models]

        if not available_models:
            logger.error("No available models to select.")
            return []

        ordered_models = sorted(available_models, key=lambda m: m.get_score(), reverse=True)
        logger.info(f"Ordered models by score: {[model.get('name') for model in ordered_models]}")
        return ordered_models

    def _attempt_task(self, task_method, prompt, max_attempts=3):
        """
        Internal method to attempt a task with retries.

        Args:
            task_method (callable): The method of Model to execute (e.g., execute_prompt).
            prompt (str): The prompt to use.
            max_attempts (int): Maximum number of attempts per model.

        Returns:
            str or None: The result if successful, None otherwise.
        """
        attempted_models = []
        error_info = ''

        while len(attempted_models) < len(self.models):
            models_ordered = self.select_best_models(exclude_models=attempted_models)
            if not models_ordered:
                break

            model = models_ordered[0]
            attempt = 0
            while attempt < max_attempts:
                attempt += 1
                logger.info(f"Attempt {attempt} with model '{model.get('name')}'")
                modified_prompt = prompt + error_info
                output = getattr(model, task_method)(modified_prompt)
                code = model.parse_python_code(output)

                if model.evaluate_code(code):
                    logger.info(f"Successfully generated valid code on attempt {attempt} with model '{model.get('name')}'")
                    return code
                else:
                    logger.warning(f"Generated code is invalid on attempt {attempt} with model '{model.get('name')}'")
                    error_info = "\n# Note: Previous attempt failed due to syntax error."
                    model.adjust_score(-1)  # Penalize the model for failure

            attempted_models.append(model)
            logger.info(f"Model '{model.get('name')}' failed after {max_attempts} attempts. Trying next best model.")

        logger.error("Failed to generate valid code after trying all models.")
        return None

    def getCode(self, prompt):
        """
        Generates code for the given prompt using the best available model.

        Args:
            prompt (str): The prompt describing the code to generate.

        Returns:
            str or None: The generated code if successful, None otherwise.
        """
        logger.info(f"getCode called with prompt: {prompt}")
        return self._attempt_task(task_method='execute_prompt', prompt=prompt)

    def getTestCode(self, prompt):
        """
        Generates test code for the given prompt using the best available model.

        Args:
            prompt (str): The prompt describing the test code to generate.

        Returns:
            str or None: The generated test code if successful, None otherwise.
        """
        logger.info(f"getTestCode called with prompt: {prompt}")
        return self._attempt_task(task_method='execute_prompt', prompt=prompt)
