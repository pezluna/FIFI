import sys
from session import Sessions
from label import Label
from model import HeaderModel, StatsModel, EnsembleModel

isReset = False
try:
    if len(sys.argv) == 2:
        if sys.argv[1] == "R" or sys.argv[1] == "r":
            isReset = True
except:
    raise Exception("Invalid argument. Please provide a valid argument.")

# Initialize sessions
sessions = Sessions()

try:
    if isReset:
        sessions.reset()

        sessions.save()
    else:
        sessions.load()
        print("Sessions loaded.")
        print("Length of Session: ", len(sessions.sessions["session"]))
except:
    raise Exception("Sessions file or raw files are not found or corrupted.")

# Split sessions into train and test
sessions.split_train_test()
print("Train and test data split completed.")
print("Length of Train: ", len(sessions.sessions["train"]["body"]))
print("Length of Test: ", len(sessions.sessions["test"]["label"]))
print("Train Label: ", set(sessions.sessions["train"]["body"]))
print("Test Label: ", set(sessions.sessions["test"]["label"]))

# Train the model
print("Training the model...")

branch_1 = HeaderModel()
branch_2 = StatsModel()

# Ensemble Model
# Need to implement the ensemble model
ensemble_model = EnsembleModel(branch_1, branch_2)

# Save the model
print("Saving the model...")

branch_1.save()
branch_2.save()
ensemble_model.save()

print("Model training and testing completed.")
