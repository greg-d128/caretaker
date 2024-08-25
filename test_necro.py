# This code is simply meant to illustrate how overseer can be run.


import caretaker
#from caretaker import ExceptionHandler

#@ExceptionHandler
#def square_number(num):
#    """Returns a square of a number and subtract 3."""
#    raise Exception("This is an error")

    
def square_number():
    raise Exception("This is an error")

print(f"Square of 10 is {square_number(10)}")
print(f"Square of 5 is {square_number(5)}")
print(f"Square of -3 is {square_number(-3)}")
print(f"Square of -3.2 is {square_number(-3.2)}")
print(f"Square of 'hello' is {square_number('hello')}")
print(f"Square of 5 is {square_number(5)}")
