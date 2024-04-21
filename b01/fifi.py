import sys
from session import Sessions
from model import PacketModel, StatsModel

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
# sessions.save("split_completed.json")

# Train the model
print("Training the model...")

# Packet model
packet_model = PacketModel(purpose='fingerprint', model='cnn')

pred_y = packet_model.train(X_train, y_train, X_test)
print("Packet model trained.")