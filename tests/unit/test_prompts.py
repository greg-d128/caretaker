import unittest
from caretaker.prompts.prompt import Prompt

class TestPrompt(unittest.TestCase):
    
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
    
    def test_init(self):
        # Check if the required parameters are correctly extracted
        expected_required_params = ["customer_name", "report_date"]
        self.assertEqual(self.report_prompt.required_params, expected_required_params)
        
        # Check other attributes
        self.assertEqual(self.report_prompt.name, "ReportPrompt")
        self.assertEqual(self.report_prompt.instruction_type, "text_generation")
    
    def test_match_success(self):
        context = {
            "customer_name": "Acme Corp",
            "report_date": "2023-10-01"
        }
        self.assertTrue(self.report_prompt.match(context))
    
    def test_match_failure(self):
        context_missing_customer = {
            "report_date": "2023-10-01"
        }
        context_missing_date = {
            "customer_name": "Acme Corp"
        }
        
        self.assertFalse(self.report_prompt.match(context_missing_customer))
        self.assertFalse(self.report_prompt.match(context_missing_date))
    
    def test_get_success(self):
        context = {
            "customer_name": "Acme Corp",
            "report_date": "2023-10-01"
        }
        expected_output = "Generate a report for Acme Corp on 2023-10-01."
        self.assertEqual(self.report_prompt.get(context), expected_output)
    
    def test_get_failure_missing_param(self):
        context_missing_customer = {
            "report_date": "2023-10-01"
        }
        
        with self.assertRaises(ValueError) as cm:
            self.report_prompt.get(context_missing_customer)
        
        self.assertEqual(str(cm.exception), "Missing required parameter: 'customer_name'")
    
    def test_validate_success(self):
        response = "This is a valid report."
        self.assertTrue(self.report_prompt.validate(response))
    
    def test_validate_failure(self):
        response_invalid_1 = "short"
        response_invalid_2 = "invalid response"
        
        self.assertFalse(self.report_prompt.validate(response_invalid_1))
        self.assertFalse(self.report_prompt.validate(response_invalid_2))

class MockValidationPrompt:
    def __init__(self, validation_func):
        self.validation_func = validation_func
    
    def validate(self, response):
        return self.validation_func(response)

if __name__ == "__main__":
    unittest.main()