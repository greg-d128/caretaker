from datetime import datetime, timezone
import dateutil
import caretaker.config as config
from zoneinfo import ZoneInfo

class Model:
    def __init__(self, name, release_date, successes=0, executions=0, speed=0, info={}):
        self.name = name
        # this is technically a bug, but for the calculations I am doing, +/- a day
        # does not make a whole lot of difference
        if type(release_date) == type(''):
            self.release_date = dateutil.parser.parse(release_date)  
        else:
            self.release_date = release_date
            
        self.successes = successes
        self.executions = executions
        self.speed = speed  # sum of all the executions times
        self.info = info

    def calculate_score(self):
        current_date = datetime.now(tz=self.release_date.tzinfo)
        days_since_release = (current_date - self.release_date).days
        age_score = max(0, 1 - (days_since_release * config.age_point_loss_per_day))

        if self.executions > 0:
            accuracy_score = self.successes / self.executions
            speed_score = min(1, max(0, 1 / ((self.speed/config.max_model_runtime + 0.001) / self.executions)))  
        else:
            accuracy_score = 0    
            speed_score = 0
        
        total_score = (
            age_score * config.age_weight +
            accuracy_score * config.accuracy_weight +
            speed_score * config.speed_weight
        )
        return total_score

    def __repr__(self):
        return f"Model(name={self.name} score={self.calculate_score()})"