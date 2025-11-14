# Model manager

from datetime import datetime
import pprint
import ollama
import caretaker.models.model as model
import caretaker.config as config
from zoneinfo import ZoneInfo


class ModelManager:
    def __init__(self):
        self.models = []
        self.last_refresh = None
        self.refresh_models()

    def refresh_models(self):
        
        if self.last_refresh:
            if (datetime.now(ZoneInfo('UTC')) - self.last_refresh).total_seconds() < config.model_refresh_interval:
                return
        
        for m in ollama.list().get('models',[]):
            self.models.append(model.Model(name = next((m[k] for k in ['name','model','digest'] if k in m), 'Unknown'), 
                                     release_date = m.get('modified_at', datetime.now()),
                                     speed = 0,
                                     info = m))

        self.last_refresh = datetime.now(ZoneInfo('UTC'))

    def get_best_models(self):
        valid_models = [(model, model.calculate_score()) for model in self.models]
        sorted_models = sorted(valid_models, key=lambda x: x[1], reverse=True)
        return [model for model, score in sorted_models]

    def execute_prompt(self, prompt, context={}):
        successes = []
        for model in self.get_best_models():
            start_time = datetime.now()
            try:
                response = ollama.generate(model.name, prompt.get(context))
                duration = (datetime.now() - start_time).total_seconds()
                if self.validate_result(response, prompt): 
                    success = True
                else:
                    success = False  
                self.update_model_stats(model, speed=duration, success=success)
                successes.append((model, response))
            except Exception as e:
                print(f"Failed to execute prompt with model {model.name}: {e}")
                duration = (datetime.now() - start_time).total_seconds()
                self.update_model_stats(model, speed=duration, success=False)
        return successes

    def validate_result(self, response, prompt):
        "Performs a validation whether this response is a good reply to the question"
        return prompt.validate(response)

    def update_model_stats(self, model, speed=60, success=True):
        if success:
            model.successes += 1
        model.executions += 1
        model.speed += speed
