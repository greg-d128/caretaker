# Configuration area for Caretaker
import logging
import logging.config

logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'ai': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'necromancer': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'decorators': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'prompts': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },

       'config': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },

    }
}

# Apply the logging configuration
logging.config.dictConfig(logging_config)

logger = logging.getLogger("config")

logger.info("logger instantiated")


# Define configurable parameters for scoring Models
AGE_POINT_LOSS_PER_DAY = 0.01
SIZE_POINTS_PER_BILLION_PARAMETERS = 10
FAILURE_PENALTY_PER_FAILURE = 1.0
QUANTIZATION_LEVEL_PENALTY = {
    'q4': -5,
    'q8': 5,
}
SIZE_PENALTY_THRESHOLD = 30  # Billion parameters
SIZE_PENALTY_FACTOR = 0.5  # Penalty per billion parameters above threshold





model_preference = ["command-r:latest", "deepseek-coder-v2:latest", "llama3.1:latest", 
                    "llama3.1:70b", "mistral-nemo:latest"]

# This is against python best practices by violating "Explicit is better than implicit" 
# I am automatically including "necromancer" activation which will include 
# necromancer in global exception hook.
# If this ever goes beyond demonstration, I can disable that behavior here.
activate = ('necromancer')

logger.info("models defined")