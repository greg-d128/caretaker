# Configuration container for the Caretaker

import ollama

# Add later: list all available ollama models and try to select one?
# Perhaps have prompts that work with specific model families?

model = "deepseek-coder-v2:latest"

prompt="""### Problem:
A Python function has encountered an error. Below is the source code of the function and the error message generated.

### Source Code:
{source_code}

### Error Message:
{error_message}

### Task:
Please analyze the source code and the error message. Identify the root cause of the error and suggest a revised version of the function that fixes the issue. Ensure the revised function handles this and other common error conditions gracefully.
Provide the complete fixed function. Do not include sample code.

### Response:
"""

