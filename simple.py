# This code is simply meant to illustrate how overseer
# can run as a necromancer and fix code that has already failed
#


import caretaker



def square_number():
    raise Exception("This is an error")

print(f"Square of 10 is {square_number(10)}")
print(f"Square of 5 is {square_number(5)}")
print(f"Square of -3 is {square_number(-3)}")
print(f"Square of -3.2 is {square_number(-3.2)}")
print(f"Square of 'hello' is {square_number('hello')}")
print(f"Square of 5 is {square_number(5)}")
