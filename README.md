# Readme

This is a simple demonstration project. More like this is possible at this point. Use at your own risk. This code is ultimately non-deterministic and nobody knows what might happen.

Importing this code will give a simple python script rudimentary way of fixing itself.
This scripts registers itself as a global exception hook, retrieves the source code that failed, executes llm to fix the code, substitutes it back in and continues execution as if nothing happened.

Simple, eh?

# Components

## Configuration

Configuration area for the module. This is simply a python module that is loaded and referenced. Easy and flexible. Security is not a consideration since:

A) This project is meant to be a library / agent that is included within another project, having complete and total control of that project.
B) We are running AI within our code and allowing it to make decisions on the fly. 
C) There is no end-user facing configuration planned at this point.

## AI
System of selecting and listing available models. To be expanded later. 
Key functionality:
- Assume that capability may change over time. There has to be a method of re-examining capabilities and adding to them.
- Allow for models to be deleted, even if they were found before. 
- Allow to handle models (at least try to), even if they are new.
- Optionally allow to download models?

## Prompts
System of having and selecting one of multiple prompts. 
Key Functionality:
- Some prompts work with some models, and not others.
- Some prompts may require different information. Thankfully we can try different prompts and get an error if information is not available.
- Each prompt should have some way of deciding if a model can be used to evaluate it.

## Decorators

Currently only one decorator. Others are in the planning stages. Please have a look at issues inside github if you are interested.

Decorator is capable of catching and monitoring a single feature, while recording information about that section of code. 


## Necromancer

Last ditch effort to respond to an unhandled exception. At this stage the program is effectively dead and the stack has unravelled. More testing is needed whether necromancer can restore a complex program, but should work for simple scripts.

While this mode of running is simple and impressive, it is primairly included here as a demonstration. At the stage of life when necromancer is activated, the program is effectively dead. All the stack has been traversed up and the only remaining thing is to output the stack trace to screen or log. This code will attempt to ressurect and re-start the code execution, which is a very interesting concept.

At this stage this will only work for simple scripts. If at any point in the stack we catch and then re-raise an exception, necromancer would likely be get very confused.


# Installation

## Ollama

Need ollama installed together with 
pip install ollama.

Need to download an appropriate model and set it inside caretaker/config.py. While you are at it, feel free to improve on the prompt.




# Issues and future work

There are several issues with this code. Some (most probably) are fixable.

1. This package may not install properly at this time.  I am trying to resolve naming issues.

2. It only modifies the code in memory, does not write it back out to the filesystem. 

3. This code is currently working with ollama only, although it allows for capture of other models and methods of execution (not fully implemented yet). Need to create a process of selecting a best model.

4. Catching it at global exception hook means the program is already dead. Restarting execution (if the failure happened in a loop, etc), is tricky. Necromancer is a pure demonstration of what might be possible. Decorators are the future.

5. Several different decorators are in the design / partial implemntation stages. No guarantee any of them work. 
