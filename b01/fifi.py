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

        # Initialize label
        label = Label()
        try:
            label.load()
        except:
            raise Exception("Label file not found.")

        sessions.map_labels(label.label)

        sessions.save()
    else:
        sessions.load()
        print("Sessions loaded.")
        print("Length of Metadata: ", len(sessions.sessions["metadata"]))
        print("Length of Labels: ", len(sessions.sessions["label"]))
except:
    raise Exception("Sessions file or raw files are not found or corrupted.")

# Split sessions into train and test
sessions.split_train_test()
print("Train and test data split completed.")
print("Length of Train Data: ", len(sessions.sessions["train"]["body"]))
print("Length of Test Data: ", len(sessions.sessions["test"]["body"]))

print("Label in Train Data: ", set(sessions.sessions["train"]["label"]))
print("Label in Test Data: ", set(sessions.sessions["test"]["label"]))

# Train the model
print("Training the model...")

branch_1 = HeaderModel()
branch_2 = StatsModel()

branch_1.train(sessions.sessions, label.labels)
branch_2.train(sessions.sessions, label.labels)

# Ensemble Model
# Need to implement the ensemble model
ensemble_model = EnsembleModel(branch_1, branch_2)

# Save the model
print("Saving the model...")

branch_1.save()
branch_2.save()
ensemble_model.save()

# Test the model
branch_1.test(sessions.sessions, label.labels)
branch_2.test(sessions.sessions, label.labels)

print("Model training and testing completed.")
