# Simple decorator test for exception handling
import caretaker
from caretaker.decorators import ExceptionHandler

@ExceptionHandler
def ReturnSquare(num):
    "Returns a square of a number"
    return num*num

print(f"3 = {ReturnSquare('d')}")

print(f"2 = {ReturnSquare(2)}")