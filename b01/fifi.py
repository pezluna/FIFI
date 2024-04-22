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

# Load the model
print("Model loading...")

rf_model = StatsModel(mode=mode, model='rf')
xgb_model = StatsModel(mode=mode, model='xgb')
cnn_model = PacketModel(mode=mode, model='cnn')
lstm_model = PacketModel(mode=mode, model='lstm')

ensemble_rf_cnn = EnsembleClassifier(models={
    'packet': cnn_model.model,
    'stats': rf_model.model
}, mode=mode)

ensemble_xgb_cnn = EnsembleClassifier(models={
    'packet': cnn_model.model,
    'stats': xgb_model.model
}, mode=mode)

ensemble_rf_lstm = EnsembleClassifier(models={
    'packet': lstm_model.model,
    'stats': rf_model.model
}, mode=mode)

ensemble_xgb_lstm = EnsembleClassifier(models={
    'packet': lstm_model.model,
    'stats': xgb_model.model
}, mode=mode)

print("Model loaded.")

# Train the model
print("Training the model...")

packet_X_train, packet_y_train, packet_X_test = cnn_model.preprocess(X_train, y_train, X_test)
packet_y_train = np.array(packet_y_train)
stats_X_train, stats_y_train, stats_X_test = rf_model.preprocess(X_train, y_train, X_test)
stats_y_train = np.array(stats_y_train)

ensemble_rf_cnn.fit(
    {
        "packet": packet_X_train,
        "stats": stats_X_train
    },
    packet_y_train
)

ensemble_xgb_cnn.fit(
    {
        "packet": packet_X_train,
        "stats": stats_X_train
    },
    packet_y_train
)

ensemble_rf_lstm.fit(
    {
        "packet": packet_X_train,
        "stats": stats_X_train
    },
    packet_y_train
)

ensemble_xgb_lstm.fit(
    {
        "packet": packet_X_train,
        "stats": stats_X_train
    },
    packet_y_train
)

lstm_model.model.fit(packet_X_train, packet_y_train, epochs=50, batch_size=10, verbose=1)
cnn_model.model.fit(packet_X_train, packet_y_train, epochs=50, batch_size=10, verbose=1)
rf_model.model.fit(stats_X_train, stats_y_train)
xgb_model.model.fit(stats_X_train, stats_y_train)

print("Training completed.")

# Evaluate the model
print("Evaluating the model...")
predictions_ensemble_rf_cnn = ensemble_rf_cnn.predict(
    {
        "packet": packet_X_test,
        "stats": stats_X_test
    }
)

predictions_ensemble_xgb_cnn = ensemble_xgb_cnn.predict(
    {
        "packet": packet_X_test,
        "stats": stats_X_test
    }
)

predictions_ensemble_rf_lstm = ensemble_rf_lstm.predict(
    {
        "packet": packet_X_test,
        "stats": stats_X_test
    }
)

predictions_ensemble_xgb_lstm = ensemble_xgb_lstm.predict(
    {
        "packet": packet_X_test,
        "stats": stats_X_test
    }
)

predictions_lstm = lstm_model.model.predict(packet_X_test)
predictions_cnn = cnn_model.model.predict(packet_X_test)
predictions_rf = rf_model.model.predict(stats_X_test)
predictions_xgb = xgb_model.model.predict(stats_X_test)

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

if final_y_test.dtype != predictions_rf.dtype:
    final_y_test = final_y_test.astype(predictions_rf.dtype)

accuracy_rf = accuracy_score(final_y_test, predictions_rf)
accuracy_xgb = accuracy_score(final_y_test, predictions_xgb)
predictions_cnn = np.argmax(predictions_cnn, axis=1)
accuracy_cnn = accuracy_score(final_y_test, predictions_cnn)
predictions_lstm = np.argmax(predictions_lstm, axis=1)
accuracy_lstm = accuracy_score(final_y_test, predictions_lstm)
accuracy_ensemble_rf_cnn = accuracy_score(final_y_test, predictions_ensemble_rf_cnn)
accuracy_ensemble_xgb_cnn = accuracy_score(final_y_test, predictions_ensemble_xgb_cnn)
accuracy_ensemble_rf_lstm = accuracy_score(final_y_test, predictions_ensemble_rf_lstm)
accuracy_ensemble_xgb_lstm = accuracy_score(final_y_test, predictions_ensemble_xgb_lstm)

print("Accuracy RF: ", accuracy_rf)
print("Accuracy XGB: ", accuracy_xgb)
print("Accuracy CNN: ", accuracy_cnn)
print("Accuracy LSTM: ", accuracy_lstm)
print("Accuracy Ensemble RF-CNN: ", accuracy_ensemble_rf_cnn)
print("Accuracy Ensemble XGB-CNN: ", accuracy_ensemble_xgb_cnn)
print("Accuracy Ensemble RF-LSTM: ", accuracy_ensemble_rf_lstm)
print("Accuracy Ensemble XGB-LSTM: ", accuracy_ensemble_xgb_lstm)

# Save Confusion Matrix
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

cm_rf = confusion_matrix(final_y_test, predictions_rf)
plt.figure(figsize=(10, 7))
sns.heatmap(cm_rf, annot=True, fmt='d')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig("rf_confusion_matrix.png")

cm_xgb = confusion_matrix(final_y_test, predictions_xgb)
plt.figure(figsize=(10, 7))
sns.heatmap(cm_xgb, annot=True, fmt='d')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig("xgb_confusion_matrix.png")

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

cm_ensemble_rf = confusion_matrix(final_y_test, predictions_ensemble_rf_cnn)
plt.figure(figsize=(10, 7))
sns.heatmap(cm_ensemble_rf, annot=True, fmt='d')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig("ensemble_rf_cnn_confusion_matrix.png")

cm_ensemble_xgb = confusion_matrix(final_y_test, predictions_ensemble_xgb_cnn)
plt.figure(figsize=(10, 7))
sns.heatmap(cm_ensemble_xgb, annot=True, fmt='d')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig("ensemble_xgb_cnn_confusion_matrix.png")
