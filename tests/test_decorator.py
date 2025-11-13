# Testing decorators
import sys
from pathlib import Path

# Add parent directory to sys.path
parent_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(parent_dir))


from caretaker.decorators import ExceptionHandler


@ExceptionHandler
def half(x):
    """Returns half of the incoming parameter"""
    return x/2


if __name__=='__main__':
    print(f"Testing decorators: ")
    print(f"Expected {half(4)} = 2")
    print(f"Expected {half(None)}=None")
    print(f"Expected {half('hello world')}=??")