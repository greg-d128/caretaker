# 
# Caretaker LLM rewriter
# Dynamically fixes and manages the application
#

import caretaker.config as config
import caretaker.master as master
import sys

# This setups up an audit hook 
orig_exc = sys.excepthook
sys.excepthook = master.exc
