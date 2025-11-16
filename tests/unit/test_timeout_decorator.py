# tests/test_timeout_decorator.py
import unittest
from caretaker.util.timeout import timeout, TimeoutError

class TestTimeoutDecorator(unittest.TestCase):
    def test_function_within_timeout(self):
        @timeout(5)
        def fast_function():
            return "Success"

        self.assertEqual(fast_function(), "Success")

    def test_function_exceeds_timeout(self):
        @timeout(1)
        def slow_function():
            import time
            time.sleep(2)  # This should exceed the timeout

        with self.assertRaises(TimeoutError) as context:
            slow_function()

        self.assertIn("timed out after 1 seconds", str(context.exception))

    def test_function_raises_exception(self):
        @timeout(5)
        def error_function():
            raise ValueError("Something went wrong")

        with self.assertRaises(ValueError) as context:
            error_function()

        self.assertEqual(str(context.exception), "Something went wrong")

    def test_function_with_args_and_kwargs(self):
        @timeout(5)
        def function_with_params(a, b, c=None):
            return f"a={a}, b={b}, c={c}"

        result = function_with_params(1, 2, c=3)
        self.assertEqual(result, "a=1, b=2, c=3")

    def test_function_no_args(self):
        @timeout(5)
        def no_args_function():
            return "No args"

        self.assertEqual(no_args_function(), "No args")

if __name__ == '__main__':
    unittest.main()