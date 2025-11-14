# This file is used for configuration



# Define configurable parameters for scoring Models
age_point_loss_per_day = 0.01

age_weight = 1
accuracy_weight = 1
speed_weight = 1

# how often should we refresh model information
# in seconds, useful value is probably 86400 - 1 day
model_refresh_interval=3600

# Desired maximum time (in seconds) for how long a model should run to 
# execute a query and provide results.
# Used both in scoring a model and as a timeout.
max_model_runtime = 300


