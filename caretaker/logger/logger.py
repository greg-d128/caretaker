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
            'level': 'ERROR',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
        'file':{
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename':'logs/caretaker.log',
            'formatter':'standard',
            'mode':'a',
        }
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['console','file'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'ai': {
            'handlers': ['console','file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'necromancer': {
            'handlers': ['console','file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'decorators': {
            'handlers': ['console','file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'prompts': {
            'handlers': ['console','file'],
            'level': 'DEBUG',
            'propagate': False,
        },

       'config': {
            'handlers': ['console','file'],
            'level': 'DEBUG',
            'propagate': False,
        },

    }
}

# Apply the logging configuration
logging.config.dictConfig(logging_config)

logger = logging.getLogger("config")

logger.info("logger instantiated")