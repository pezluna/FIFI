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
X_train, y_train, X_test, y_test = sessions.get_train_test_data()
print("Train and test data split completed.")

# Train the model
print("Training the model...")

branch_1 = HeaderModel()
branch_2 = StatsModel()

# Ensemble Model
# Need to implement the ensemble model
ensemble_model = EnsembleModel(branch_1, branch_2)
pred_y = ensemble_model.train(sessions)

print("Model trained.")

# evaluate the model
print("Evaluating the model...")
from sklearn.metrics import accuracy_score
accuracy = accuracy_score(y_test, pred_y)
print("Accuracy: ", accuracy)
