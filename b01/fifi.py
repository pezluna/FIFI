import sys
from session import Sessions
from model import PacketModel, StatsModel, EnsembleClassifier, embedding
import numpy as np

from scikeras.wrappers import KerasClassifier
from sklearn.metrics import accuracy_score

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
# Packet model
packet_model = PacketModel(mode=mode, model='cnn')
packet_X_train, packet_y_train, packet_X_test = packet_model.preprocess(X_train, y_train, X_test)
packet_y_train = np.array(packet_y_train)

# Stats model
stats_model = StatsModel(mode=mode, model='rf')
stats_X_train, stats_y_train, stats_X_test = stats_model.preprocess(X_train, y_train, X_test)
stats_y_train = np.array(stats_y_train)

packet_keras_model = KerasClassifier(
    build_fn=lambda: packet_model.model,
    epochs = 50,
    batch_size = 10,
    verbose = 1
)

# Ensemble classifier
ensemble = EnsembleClassifier(models={
    'packet': packet_model.model,
    'stats': stats_model.model
}, mode=mode)

ensemble.fit(
    {
        "packet": packet_X_train,
        "stats": stats_X_train
    },
    packet_y_train
)

print("Training completed.")

# Evaluate the model
print("Evaluating the model...")
predictions = ensemble.predict(
    {
        "packet": packet_X_test,
        "stats": stats_X_test
    }
)

final_y_test = []
if mode == "fingerprint":
    for y in y_test:
        if y == "benign" or y == "mirai" or y == "qbot" or y == "kaiten":
            pass
        else:
            final_y_test.append(embedding[y])
else:
    for y in y_test:
        if y == "benign" or y == "mirai" or y == "qbot" or y == "kaiten":
            final_y_test.append(embedding[y])
        else:
            pass

final_y_test = np.array(final_y_test)

if final_y_test.dtype != predictions.dtype:
    final_y_test = final_y_test.astype(predictions.dtype)

accuracy = accuracy_score(final_y_test, predictions)

print("Accuracy: ", accuracy)

# CNN
stats_y_pred = stats_model.model.predict(stats_X_test)
print(set(stats_y_pred))
print(set(final_y_test))

## Confusion Matrix
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

cm = confusion_matrix(final_y_test, stats_y_pred)
plt.figure(figsize=(10, 7))
sns.heatmap(cm, annot=True, fmt='d')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig("cnn_confusion_matrix.png")
print(accuracy_score(final_y_test, stats_y_pred))

# Random Forest
stats_y_pred = stats_model.model.predict(stats_X_test)
print(set(stats_y_pred))
print(set(final_y_test))

## Confusion Matrix
cm = confusion_matrix(final_y_test, stats_y_pred)
plt.figure(figsize=(10, 7))
sns.heatmap(cm, annot=True, fmt='d')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig("rf_confusion_matrix.png")
print(accuracy_score(final_y_test, stats_y_pred))

# Ensemble
print(set(predictions))
print(set(final_y_test))

cm = confusion_matrix(final_y_test, predictions)
plt.figure(figsize=(10, 7))
sns.heatmap(cm, annot=True, fmt='d')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig("ensemble_confusion_matrix.png")
print(accuracy_score(final_y_test, predictions))