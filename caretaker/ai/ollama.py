
import ollama

def init(models):
    # add yourself to the models object
    mlist = ollama.list()
    for m in mlist['models']:
        models.register_model("ollama_"+m["name"], lambda prompt: ollama.chat(m["name"], prompt))
