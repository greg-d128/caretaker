# tests/test_model_manager.py
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from caretaker.models.manager import ModelManager
from caretaker.models.model import Model
from tests.mocks.mock_ollama import Ollama as ollama

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
        model1 = Model(name='model1', release_date='2023-10-01T12:00:00Z')
        model2 = Model(name='model2', release_date='2023-10-02T12:00:00Z')
        
        self.manager.models.append(model1)
        self.manager.models.append(model2)
        
        best_models = self.manager.get_best_models()
        self.assertEqual(best_models, [model1, model2])  # Assuming model2 is newer and thus has a higher score

    @patch('ollama.generate')
    def test_execute_prompt(self, mock_generate):
        mock_generate.side_effect = ["Response from model1", "Response from model2"]
        
        prompt_mock = MagicMock()
        prompt_mock.get.return_value = "Test Prompt"
        prompt_mock.validate.side_effect = [True, False]
        
        model1 = Model(name='model1', release_date='2023-10-01T12:00:00Z')
        model2 = Model(name='model2', release_date='2023-10-02T12:00:00Z')
        
        self.manager.models.append(model1)
        self.manager.models.append(model2)
        
        successes = self.manager.execute_prompt(prompt_mock)
        
        self.assertEqual(len(successes), 2)
        self.assertEqual(successes[0][0].name, 'model1')
        self.assertTrue(successes[0][0].successes == 1)
        self.assertTrue(successes[0][0].executions == 1)

    def test_update_model_stats(self):
        model = Model(name='model1', release_date='2023-10-01T12:00:00Z')
        
        self.manager.update_model_stats(model, speed=60, success=True)
        self.assertEqual(model.successes, 1)
        self.assertEqual(model.executions, 1)
        self.assertEqual(model.speed, 60)
        
        self.manager.update_model_stats(model, speed=30, success=False)
        self.assertEqual(model.successes, 1)  # Success count should not change
        self.assertEqual(model.executions, 2)
        self.assertEqual(model.speed, 90)

if __name__ == '__main__':
    unittest.main()