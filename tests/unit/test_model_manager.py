# tests/test_model_manager.py
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from caretaker.models.manager import ModelManager
from caretaker.models.model import Model
from tests.mocks.mock_ollama import Ollama as ollama
from caretaker import config  # Import the actual config module

class TestModelManager(unittest.TestCase):
    def setUp(self):
        self.manager = ModelManager()
        self.manager.models = []  # Clear models for each test
        self.manager.last_refresh = None

    @patch('ollama.list')
    def test_refresh_models(self, mock_list):
        mock_list.return_value = {
            'models': [
                {'name': 'model1', 'modified_at': '2023-10-01T12:00:00Z'},
                {'name': 'model2', 'modified_at': '2023-10-02T12:00:00Z'}
            ]
        }
        
        self.manager.refresh_models()
        
        self.assertEqual(len(self.manager.models), 2)
        self.assertIsNotNone(self.manager.last_refresh)

    @patch('ollama.list')
    def test_refresh_models_within_interval(self, mock_list):
        mock_list.return_value = {
            'models': [
                {'name': 'model1', 'modified_at': '2023-10-01T12:00:00Z'},
                {'name': 'model2', 'modified_at': '2023-10-02T12:00:00Z'}
            ]
        }
        
        self.manager.last_refresh = datetime.now(timezone.utc) - timedelta(seconds=1800)
        self.manager.refresh_models()
        mock_list.assert_not_called()

    def test_get_best_models(self):
        model1 = Model(name='model1', release_date=datetime.fromisoformat('2023-10-01T12:00:00+00:00'))
        model2 = Model(name='model2', release_date=datetime.fromisoformat('2023-10-02T12:00:00+00:00'))
        
        self.manager.models.append(model1)
        self.manager.models.append(model2)
        
        best_models = self.manager.get_best_models()
        self.assertEqual(best_models, [model2, model1])  # Assuming model2 is newer and thus has a higher score

    @patch('ollama.generate')
    def test_execute_prompt(self, mock_generate):
        mock_generate.side_effect = ["Response from model1", "Response from model2"]
        
        prompt_mock = MagicMock()
        prompt_mock.get_text.return_value = "Test Prompt"
        prompt_mock.validate.side_effect = [True, False]
        
        model1 = Model(name='model1', release_date=datetime.fromisoformat('2023-10-01T12:00:00+00:00'))
        model2 = Model(name='model2', release_date=datetime.fromisoformat('2023-10-02T12:00:00+00:00'))
        
        self.manager.models.append(model1)
        self.manager.models.append(model2)
        
        successes = self.manager.execute_prompt(prompt_mock)
        
        self.assertEqual(len(successes), 1)  # Only model1 should succeed
        self.assertEqual(successes[0][0].name, 'model1')
        self.assertTrue(successes[0][0].successes == 1)
        self.assertTrue(successes[0][0].executions == 1)

    @patch('ollama.generate')
    def test_execute_model_prompt_within_timeout(self, mock_generate):
        config.max_model_runtime = 5  # Set timeout to 5 seconds
        
        prompt_mock = MagicMock()
        prompt_mock.get_text.return_value = "Test Prompt"
        
        model1 = Model(name='model1', release_date=datetime.fromisoformat('2023-10-01T12:00:00+00:00'))
        
        self.manager.models.append(model1)
        
        mock_generate.return_value = "Response from model1"
            
        response = self.manager.execute_model_prompt(prompt_mock, model1)
            
        self.assertEqual(response, "Response from model1")
        mock_generate.assert_called_once_with("Test Prompt", model1.name)

    @patch('ollama.generate')
    def test_execute_model_prompt_exceeds_timeout(self, mock_generate):
        config.max_model_runtime = 1  # Set timeout to 1 second
        
        prompt_mock = MagicMock()
        prompt_mock.get_text.return_value = "Test Prompt"
        
        model1 = Model(name='model1', release_date=datetime.fromisoformat('2023-10-01T12:00:00+00:00'))
        
        self.manager.models.append(model1)
        
        mock_generate.side_effect = lambda *args: (datetime.now() + timedelta(seconds=2)).strftime('%Y-%m-%d %H:%M:%S')
            
        with self.assertRaises(TimeoutError) as context:
            self.manager.execute_model_prompt(prompt_mock, model1)
            
        self.assertIn("timed out after 1 seconds", str(context.exception))
        mock_generate.assert_called_once_with("Test Prompt", model1.name)

    @patch('ollama.generate')
    def test_execute_prompt_within_timeout(self, mock_generate):
        config.max_runtime = 5  # Set timeout to 5 seconds
        
        prompt_mock = MagicMock()
        prompt_mock.get_text.return_value = "Test Prompt"
        prompt_mock.validate.side_effect = [True, False]
        
        model1 = Model(name='model1', release_date=datetime.fromisoformat('2023-10-01T12:00:00+00:00'))
        model2 = Model(name='model2', release_date=datetime.fromisoformat('2023-10-02T12:00:00+00:00'))
        
        self.manager.models.append(model1)
        self.manager.models.append(model2)
        
        mock_generate.side_effect = ["Response from model1", "Response from model2"]
            
        successes = self.manager.execute_prompt(prompt_mock)
            
        self.assertEqual(len(successes), 1)  # Only model1 should succeed
        self.assertEqual(successes[0][0].name, 'model1')
        self.assertTrue(successes[0][0].successes == 1)
        self.assertTrue(successes[0][0].executions == 1)

    @patch('ollama.generate')
    def test_execute_prompt_exceeds_timeout(self, mock_generate):
        config.max_runtime = 1  # Set timeout to 1 second
        
        prompt_mock = MagicMock()
        prompt_mock.get_text.return_value = "Test Prompt"
        prompt_mock.validate.side_effect = [True, False]
        
        model1 = Model(name='model1', release_date=datetime.fromisoformat('2023-10-01T12:00:00+00:00'))
        model2 = Model(name='model2', release_date=datetime.fromisoformat('2023-10-02T12:00:00+00:00'))
        
        self.manager.models.append(model1)
        self.manager.models.append(model2)
        
        mock_generate.side_effect = lambda *args: (datetime.now() + timedelta(seconds=2)).strftime('%Y-%m-%d %H:%M:%S')
            
        successes = self.manager.execute_prompt(prompt_mock)
            
        self.assertEqual(len(successes), 0)  # No successful responses

    def test_validate_result(self):
        mock_prompt = MagicMock()
        mock_prompt.validate.return_value = True
        response = "Valid response"
        result = self.manager.validate_result(response, mock_prompt)
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()