import unittest
from unittest.mock import patch
from caretaker.prompts.prompt import Prompt

class TestPromptFunctional(unittest.TestCase):
    
    def setUp(self):
        self.prompt_template = "Generate a report for {customer_name} on {report_date}."
        self.validation_prompt1 = MockValidationPrompt(lambda response: "valid" in response)
        self.validation_prompt2 = MockValidationPrompt(lambda response: len(response) > 10)
        
        self.report_prompt = Prompt(
            name="ReportPrompt",
            prompt=self.prompt_template,
            instruction_type="text_generation",
            validation_prompts=[self.validation_prompt1, self.validation_prompt2]
        )
    
    def test_functional_full_flow(self):
        # Define the context
        context = {
            "customer_name": "Acme Corp",
            "report_date": "2023-10-01"
        }
        
        # Check if the context matches the required parameters
        self.assertTrue(self.report_prompt.match(context))
        
        # Get the final prompt
        expected_output = "Generate a report for Acme Corp on 2023-10-01."
        final_prompt = self.report_prompt.get(context)
        self.assertEqual(final_prompt, expected_output)
        
        # Validate the response
        response = "This is a valid and detailed report for Acme Corp on 2023-10-01."
        self.assertTrue(self.report_prompt.validate(response))
    
    def test_functional_missing_param(self):
        # Define the context with missing parameters
        context_missing_customer = {
            "report_date": "2023-10-01"
        }
        
        # Check if the context matches the required parameters
        self.assertFalse(self.report_prompt.match(context_missing_customer))
        
        # Attempt to get the final prompt and expect an error
        with self.assertRaises(ValueError) as cm:
            self.report_prompt.get(context_missing_customer)
        
        self.assertEqual(str(cm.exception), "Missing required parameter: 'customer_name'")
    
    def test_functional_invalid_response(self):
        # Define a valid context
        context = {
            "customer_name": "Acme Corp",
            "report_date": "2023-10-01"
        }
        
        # Get the final prompt
        expected_output = "Generate a report for Acme Corp on 2023-10-01."
        final_prompt = self.report_prompt.get(context)
        self.assertEqual(final_prompt, expected_output)
        
        # Define an invalid response
        invalid_response_short = "short"
        invalid_response_invalid_content = "invalid content"
        
        # Validate the invalid responses
        self.assertFalse(self.report_prompt.validate(invalid_response_short))
        self.assertFalse(self.report_prompt.validate(invalid_response_invalid_content))

class MockValidationPrompt:
    def __init__(self, validation_func):
        self.validation_func = validation_func
    
    def validate(self, response):
        return self.validation_func(response)

if __name__ == "__main__":
    unittest.main()