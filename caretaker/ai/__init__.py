# Abstraction module for AI.
# The basic idea is that this code will attemp to connect to 
# known ai modules. We cannot assume that modules are actually 
# available until we try to run them.

# Need a common API.
# list_models() - list downloaded and available models
# rewrite_code(model, question)
# available() # models available for download
# download

models={}

def scan():
    global models
    models = {}
    
    try:
        import ollama
        # add models models
        models.update({ (ollama, m['name']):m for m in ollama.list()['models']})
    except:
        pass
    print (models)


def list_models():
    return [x[1] for x in models.keys()]


def rewrite_code(instruction):
    # Implement this.



scan()