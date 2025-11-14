import string


# TODO : Validation needs thinking
class Prompt:
    def __init__(self, name, prompt, instruction_type, validation_prompts=None):
        self.name = name
        self.prompt_template = prompt
        self.instruction_type = instruction_type
        self.validation_prompts = validation_prompts or []
        
        # Use str.Formatter to parse the template and extract required fields
        formatter = string.Formatter()
        self.required_params = [field_name for _, field_name, _, _ in formatter.parse(self.prompt_template) if field_name]

    def match(self, context={}):
        """Check if all required parameters are present in the provided dictionary."""
        return all(param in context for param in self.required_params)

    def get(self, context={}):
        """Assemble the final prompt using the provided context dictionary."""
        formatter = string.Formatter()
        try:
            final_prompt = formatter.vformat(self.prompt_template, (), context)
        except KeyError as e:
            raise ValueError(f"Missing required parameter: {e}")
        return final_prompt

    def validate(self, response):
        """Validate the response against validation prompts."""
        for validation_prompt in self.validation_prompts:
            if not validation_prompt.validate(response):
                return False
        return True

