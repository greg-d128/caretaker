# Abstraction module for AI.
# The basic idea is that this code will attemp to connect to 
# known ai modules. We cannot assume that modules are actually 
# available until we try to run them.

## This file __init__ is the glue.
# It loads ollama and gets a list of models available as a list
# adds 

## Lets start with functionality we need.
import logging
import caretaker.ai.model as m
import caretaker.ai.master as master
import caretaker.config as config
import caretaker.prompts as prompts
import ollama
import pprint
import re

logger = logging.getLogger("ai")

# Load a list of models from ollama
lst = ollama.list()['models']

ai = master.AI()
ai.update(lst)


