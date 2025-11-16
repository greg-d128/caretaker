# test_model.py
import unittest
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import dateutil.parser

import caretaker.config as config
from caretaker import config
from caretaker.models.model import Model

class TestModel(unittest.TestCase):
    def setUp(self):
        self.model = Model(
            name="TestModel",
            release_date=str(datetime.now(ZoneInfo('UTC')) - timedelta(days=10)),
            successes=5,
            executions=10,
            speed=300,  # Total execution time in seconds
            info={"description": "A test model"}
        )

    def test_init(self):
        self.assertEqual(self.model.name, "TestModel")
        self.assertIsInstance(self.model.release_date, datetime)
        self.assertEqual(self.model.successes, 5)
        self.assertEqual(self.model.executions, 10)
        self.assertEqual(self.model.speed, 300)
        self.assertEqual(self.model.info, {"description": "A test model"})

    def test_calculate_score(self):
        current_date = datetime.now(tz=self.model.release_date.tzinfo)
        days_since_release = (current_date - self.model.release_date).days
        age_score = max(0, 1 - (days_since_release * config.age_point_loss_per_day))
        accuracy_score = self.model.successes / self.model.executions
        speed_score = min(1, max(0, 1 / ((self.model.speed / config.max_model_runtime + 0.001) / self.model.executions)))
        
        expected_total_score = (
            age_score * config.age_weight +
            accuracy_score * config.accuracy_weight +
            speed_score * config.speed_weight
        )
        
        self.assertAlmostEqual(self.model.calculate_score(), expected_total_score, places=5)

    def test_repr(self):
        score = self.model.calculate_score()
        expected_repr = f"Model(name={self.model.name} score={score})"
        self.assertEqual(repr(self.model), expected_repr)



if __name__ == '__main__':
    unittest.main()