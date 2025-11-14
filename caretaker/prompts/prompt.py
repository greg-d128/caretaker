
class Prompt:
    def __init__(self, name, prompt, instruction_type, preferred_params=None, required_params=None, validation_prompts=None):
        self.name = name
        self.prompt = prompt
        self.instruction_type = instruction_type
        self.preferred_params = preferred_params or []
        self.required_params = required_params or []
        self.validation_prompts = validation_prompts or []

    def match(self, available_params):
        return all(param in available_params for param in self.required_params)

    def get(self):
        # This needs fixing - Prompt should be abstract...
        # and combined with context that will complete it 
        return self.prompt
    
    def validate(self, response):
        return True
        # Validate the response against the validation prompts
        for validation_prompt in self.validation_prompts:
            if not validation_prompt.validate(response):
                return False
        return True


if __name__=='__main__':
    p = Prompt("q1", "Tell me a joke", "question")
    print (p)