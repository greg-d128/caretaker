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
from ollama import Client
import pprint
import re

logger = logging.getLogger("ai")




client=Client(host='http://192.168.2.122:11436')

# Load a list of models from ollama
lst = client.list()['models']

ai = master.AI(models=lst, client=client)



