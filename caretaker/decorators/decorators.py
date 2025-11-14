def input_validator(*required_params):
    def decorator(func):
        def wrapper(*args, **kwargs):
            available_params = list(args) + list(kwargs.values())
            for param in required_params:
                if param not in available_params:
                    raise ValueError(f"Missing required parameter: {param}")
            return func(*args, **kwargs)
        return wrapper
    return decorator

def exception_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger = Logger()
            logger.log('error', f"Exception occurred: {e}")
            handler = ExceptionHandler(prompt_library, model_manager)
            available_params = list(args) + list(kwargs.values())
            response = handler.handle_exception(e, available_params)
            logger.log('info', f"Handled exception with response: {response}")
            return response
    return wrapper