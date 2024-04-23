import sys
from session import Sessions
from model import PacketModel, embedding_botnet
import numpy as np

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

isReset = False
mode = None
try:
    if len(sys.argv) == 2:
        if sys.argv[1] == "R" or sys.argv[1] == "r":
            isReset = True
        elif sys.argv[1] == "F" or sys.argv[1] == "f":
            mode = "fingerprint"
        elif sys.argv[1] == "B" or sys.argv[1] == "b":
            mode = "botnet"
    elif len(sys.argv) == 3:
        if sys.argv[1] != "R" and sys.argv[1] != "r":
            raise Exception("Invalid argument. Please provide a valid argument.")
        isReset = True
        if sys.argv[2] == "F" or sys.argv[2] == "f":
            mode = "fingerprint"
        elif sys.argv[2] == "B" or sys.argv[2] == "b":
            mode = "botnet"
        else:
            raise Exception("Invalid argument. Please provide a valid argument.")
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

        s = {}
        for session in sessions.sessions["session"]:
            if session["label"] in s:
                s[session["label"]] += 1
            else:
                s[session["label"]] = 1
        
        print(s)
except:
    raise Exception("Sessions file or raw files are not found or corrupted.")
    
# Split sessions into train and test
sessions.split_train_test()
X_train, y_train, X_test, y_test = sessions.get_train_test_data()
print("Train and test data split completed.")

# Load the model
print("Model loading...")

cnn_model = PacketModel(mode=mode, model='cnn')
lstm_model = PacketModel(mode=mode, model='lstm')

print("Model loaded.")

# Train the model
print("Training the model...")

packet_X_train, packet_y_train, packet_X_test = cnn_model.preprocess(X_train, y_train, X_test)
packet_y_train = np.array(packet_y_train)

lstm_model.model.fit(packet_X_train, packet_y_train, epochs=10, batch_size=2)
cnn_model.model.fit(packet_X_train, packet_y_train, epochs=10, batch_size=2)

print("Training completed.")

# Evaluate the model
print("Evaluating the model...")

predictions_lstm = lstm_model.model.predict(packet_X_test)
predictions_cnn = cnn_model.model.predict(packet_X_test)

final_y_test = []

for y in y_test:
    if y == "benign" or y == "mirai" or y == "qbot" or y == "kaiten":
        final_y_test.append(embedding_botnet[y])
    else:
        pass

final_y_test = np.array(final_y_test)

predictions_cnn = np.argmax(predictions_cnn, axis=1)
predictions_lstm = np.argmax(predictions_lstm, axis=1)

if final_y_test.dtype != predictions_cnn.dtype:
    final_y_test = final_y_test.astype(predictions_cnn.dtype)

print(set(final_y_test))

print(set(predictions_cnn))
print(set(predictions_lstm))

print("-------------------")
print("CNN")
print("Accuracy: ", accuracy_score(final_y_test, predictions_cnn))
print("Precision: ", precision_score(final_y_test, predictions_cnn))
print("Recall: ", recall_score(final_y_test, predictions_cnn))
print("F1: ", f1_score(final_y_test, predictions_cnn))

print("-------------------")
print("LSTM")
print("Accuracy: ", accuracy_score(final_y_test, predictions_lstm))
print("Precision: ", precision_score(final_y_test, predictions_lstm))
print("Recall: ", recall_score(final_y_test, predictions_lstm))
print("F1: ", f1_score(final_y_test, predictions_lstm))

print("Evaluation completed.")

# Save Confusion Matrix
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

cm_cnn = confusion_matrix(final_y_test, predictions_cnn)
plt.figure(figsize=(10, 7))
sns.heatmap(cm_cnn, annot=True, fmt='d')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig("cnn_confusion_matrix.png")

cm_lstm = confusion_matrix(final_y_test, predictions_lstm)
plt.figure(figsize=(10, 7))
sns.heatmap(cm_lstm, annot=True, fmt='d')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig("lstm_confusion_matrix.png")