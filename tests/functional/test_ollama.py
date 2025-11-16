import unittest
from caretaker.prompts.prompt import Prompt
from caretaker.models.manager import ModelManager
import pprint

class TestPromptFunctionalUnmocked(unittest.TestCase):
    
    def setUp(self):
        self.prompt_template = "Tell me a joke about {object_name}."
        self.validation_prompt1 = ValidationPrompt(lambda response: "valid" in response)
        self.validation_prompt2 = ValidationPrompt(lambda response: len(response) > 10)
        
        self.joke_prompt = Prompt(
            name="JokePrompt",
            prompt=self.prompt_template,
            instruction_type="text_generation",
            validation_prompts=[self.validation_prompt1, self.validation_prompt2]
        )
        self.manager = ModelManager()
    
    def test_functional_ollama(self):
        # Define the context
        context = {
            "object_name": "cars"
        }
        
        ret = self.manager.execute_prompt(self.joke_prompt, context)
        pprint.pprint(ret)
        pprint.pprint(self.manager.get_best_models())
        # Check if the context matches the required parameters
        #self.assertTrue(self.report_prompt.match(context))
        
        # Get the final prompt
        #expected_output = "Tell me a joke about cars."
        #final_prompt = self.report_prompt.get(context)
        #self.assertEqual(final_prompt, expected_output)
        
        # Validate the response
        #response = "This is a valid and detailed report for Acme Corp on 2023-10-01."
        #self.assertTrue(self.report_prompt.validate(response))
    

class ValidationPrompt:
    def __init__(self, validation_func):
        self.validation_func = validation_func
    
    def validate(self, response):
        return self.validation_func(response)

if __name__ == "__main__":
    unittest.main()