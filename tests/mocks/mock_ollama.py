# ollama.py (Mock implementation)
class Ollama:
    def list(self):
        return {
            'models': [
                {'name': 'model1', 'modified_at': '2023-10-01T12:00:00Z'},
                {'name': 'model2', 'modified_at': '2023-10-02T12:00:00Z'}
            ]
        }

    def generate(self, model_name, prompt):
        if model_name == 'model1':
            return "Response from model1"
        elif model_name == 'model2':
            return "Response from model2"
        else:
            raise Exception("Model not found")

ollama = Ollama()