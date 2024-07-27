# Readme

This is a simple demonstration project. More like this is possible at this point. Use at your own risk. This code is ultimately non-deterministic and nobody knows what might happen.

Importing this code will give a simple python script rudimentary way of fixing itself.
This scripts registers itself as a global exception hook, retrieves the source code that failed, executes llm to fix the code, substitutes it back in and continues execution as if nothing happened.

Simple, eh?

# Installation

## Ollama

Need ollama installed together with 
pip install ollama.

Need to download an appropriate model and set it inside caretaker/config.py. While you are at it, feel free to improve on the prompt.




# Issues and future work

There are several issues with this code. Some (most probably) are fixable.

1. Simple scripts for now, cannot handle injecting into an object. Actually, I think it can, I just messed up with the stack and need to retrieve it properly.

2. It only modifies the code in memory, does not write it back out to the filesystem. 

3. There needs to be a system to figure out which model from ollama to run, there may be prompts specific to models. We want this to figure out what to do even a year later, when models may be different. Could it download a model for itself and then run it?

4. Catching it at global exception hook means the program is already dead. Restarting execution (if the failure happened in a loop, etc), is tricky.

5. A lot of the above can be handled by introducing a decorator (coming next). That will allow me to catch errors at a specific section of a code, store and retrieve different versions of related code from a database, catch, re-run and return code as if nothing happened, store things like specific prompts and intents. Kind of like an advanced error handler.

