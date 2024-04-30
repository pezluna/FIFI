import sys
import os
from session import Sessions
from model import PacketModel, StatsModel, EnsembleClassifier, embedding_botnet, embedding_fingerprint
import numpy as np
from datetime import datetime

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
except:
    raise Exception("Sessions file or raw files are not found or corrupted.")

# Print current sessions information
print("Current sessions information:")
print("Length of Session: ", len(sessions.sessions["session"]))
label_set = set()
for session in sessions.sessions["session"]:
    label_set.add(session.label)
print("Label set: ", label_set)
info = {k: 0 for k in label_set}

for session in sessions.sessions["session"]:
    info[session.label] += len(session.body)

print(info)
    
# Split sessions into train and test
sessions.split_train_test()
X_train, y_train, X_test, y_test = sessions.get_train_test_data()
print("Train and test data split completed.")
print("Train data length: ", len(X_train))
print("Test data length: ", len(X_test))
print("Train data label set: ", len(set(y_train)))
print("Test data label set: ", len(set(y_test)))

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

lstm_model.history_lstm = lstm_model.model.fit(packet_X_train, packet_y_train, epochs=100, batch_size=4)
cnn_model.history_cnn = cnn_model.model.fit(packet_X_train, packet_y_train, epochs=100, batch_size=4)
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
            final_y_test.append(embedding_fingerprint[y])
else:
    for y in y_test:
        if y == "benign" or y == "mirai" or y == "qbot" or y == "kaiten":
            final_y_test.append(embedding_botnet[y])
        else:
            pass

final_y_test = np.array(final_y_test)

if final_y_test.dtype != predictions_rf.dtype:
    final_y_test = final_y_test.astype(predictions_rf.dtype)

predictions_cnn = np.argmax(predictions_cnn, axis=1)
predictions_lstm = np.argmax(predictions_lstm, axis=1)

print(set(final_y_test))
print(set(predictions_rf))
print(set(predictions_xgb))
print(set(predictions_cnn))
print(set(predictions_lstm))
print(set(predictions_ensemble_rf_cnn))
print(set(predictions_ensemble_xgb_cnn))
print(set(predictions_ensemble_rf_lstm))
print(set(predictions_ensemble_xgb_lstm))

print("-------------------")
print("RF")
print("Accuracy: ", accuracy_score(final_y_test, predictions_rf))
print("Precision: ", precision_score(final_y_test, predictions_rf, average='macro'))
print("Recall: ", recall_score(final_y_test, predictions_rf, average='macro'))
print("F1: ", f1_score(final_y_test, predictions_rf, average='macro'))

print("-------------------")
print("XGB")
print("Accuracy: ", accuracy_score(final_y_test, predictions_xgb))
print("Precision: ", precision_score(final_y_test, predictions_xgb, average='macro'))
print("Recall: ", recall_score(final_y_test, predictions_xgb, average='macro'))
print("F1: ", f1_score(final_y_test, predictions_xgb, average='macro'))

print("-------------------")
print("CNN")
print("Accuracy: ", accuracy_score(final_y_test, predictions_cnn))
print("Precision: ", precision_score(final_y_test, predictions_cnn, average='macro'))
print("Recall: ", recall_score(final_y_test, predictions_cnn, average='macro'))
print("F1: ", f1_score(final_y_test, predictions_cnn, average='macro'))

print("-------------------")
print("LSTM")
print("Accuracy: ", accuracy_score(final_y_test, predictions_lstm))
print("Precision: ", precision_score(final_y_test, predictions_lstm, average='macro'))
print("Recall: ", recall_score(final_y_test, predictions_lstm, average='macro'))
print("F1: ", f1_score(final_y_test, predictions_lstm, average='macro'))

print("-------------------")
print("Ensemble RF-CNN")
print("Accuracy: ", accuracy_score(final_y_test, predictions_ensemble_rf_cnn))
print("Precision: ", precision_score(final_y_test, predictions_ensemble_rf_cnn, average='macro'))
print("Recall: ", recall_score(final_y_test, predictions_ensemble_rf_cnn, average='macro'))
print("F1: ", f1_score(final_y_test, predictions_ensemble_rf_cnn, average='macro'))

print("-------------------")
print("Ensemble XGB-CNN")
print("Accuracy: ", accuracy_score(final_y_test, predictions_ensemble_xgb_cnn))
print("Precision: ", precision_score(final_y_test, predictions_ensemble_xgb_cnn, average='macro'))
print("Recall: ", recall_score(final_y_test, predictions_ensemble_xgb_cnn, average='macro'))
print("F1: ", f1_score(final_y_test, predictions_ensemble_xgb_cnn, average='macro'))

print("-------------------")
print("Ensemble RF-LSTM")
print("Accuracy: ", accuracy_score(final_y_test, predictions_ensemble_rf_lstm))
print("Precision: ", precision_score(final_y_test, predictions_ensemble_rf_lstm, average='macro'))
print("Recall: ", recall_score(final_y_test, predictions_ensemble_rf_lstm, average='macro'))
print("F1: ", f1_score(final_y_test, predictions_ensemble_rf_lstm, average='macro'))

print("-------------------")
print("Ensemble XGB-LSTM")
print("Accuracy: ", accuracy_score(final_y_test, predictions_ensemble_xgb_lstm))
print("Precision: ", precision_score(final_y_test, predictions_ensemble_xgb_lstm, average='macro'))
print("Recall: ", recall_score(final_y_test, predictions_ensemble_xgb_lstm, average='macro'))
print("F1: ", f1_score(final_y_test, predictions_ensemble_xgb_lstm, average='macro'))

print("Evaluation completed.")

# Save Confusion Matrix
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

plt.rc('font', size=20)

RESULT_PATH = f"results/{datetime.now().strftime('%Y%m%d%H%M%S')}-{mode}/"

if not os.path.exists(RESULT_PATH):
    os.makedirs(RESULT_PATH)

cm_rf = confusion_matrix(final_y_test, predictions_rf)
plt.figure(figsize=(20, 15))
sns.heatmap(cm_rf, annot=True, fmt='d', cmap='YlOrBr')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig(RESULT_PATH + "rf_confusion_matrix.png")

cm_xgb = confusion_matrix(final_y_test, predictions_xgb)
plt.figure(figsize=(20, 15))
sns.heatmap(cm_xgb, annot=True, fmt='d', cmap='YlOrBr')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig(RESULT_PATH + "xgb_confusion_matrix.png")

cm_cnn = confusion_matrix(final_y_test, predictions_cnn)
plt.figure(figsize=(20, 15))
sns.heatmap(cm_cnn, annot=True, fmt='d', cmap='YlOrBr')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig(RESULT_PATH + "cnn_confusion_matrix.png")

cm_lstm = confusion_matrix(final_y_test, predictions_lstm)
plt.figure(figsize=(20, 15))
sns.heatmap(cm_lstm, annot=True, fmt='d', cmap='YlOrBr')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig(RESULT_PATH + "lstm_confusion_matrix.png")

cm_ensemble_rf = confusion_matrix(final_y_test, predictions_ensemble_rf_cnn)
plt.figure(figsize=(20, 15))
sns.heatmap(cm_ensemble_rf, annot=True, fmt='d', cmap='YlOrBr')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig(RESULT_PATH + "ensemble_rf_cnn_confusion_matrix.png")

cm_ensemble_xgb = confusion_matrix(final_y_test, predictions_ensemble_xgb_cnn)
plt.figure(figsize=(20, 15))
sns.heatmap(cm_ensemble_xgb, annot=True, fmt='d', cmap='YlOrBr')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig(RESULT_PATH + "ensemble_xgb_cnn_confusion_matrix.png")

cm_ensemble_rf_lstm = confusion_matrix(final_y_test, predictions_ensemble_rf_lstm)
plt.figure(figsize=(20, 15))
sns.heatmap(cm_ensemble_rf_lstm, annot=True, fmt='d', cmap='YlOrBr')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig(RESULT_PATH + "ensemble_rf_lstm_confusion_matrix.png")

cm_ensemble_xgb_lstm = confusion_matrix(final_y_test, predictions_ensemble_xgb_lstm)
plt.figure(figsize=(20, 15))
sns.heatmap(cm_ensemble_xgb_lstm, annot=True, fmt='d', cmap='YlOrBr')
plt.xlabel('Predicted')
plt.ylabel('Truth')
plt.savefig(RESULT_PATH + "ensemble_xgb_lstm_confusion_matrix.png")

print("Confusion matrices saved.")

# Save epoch-loss graph
plt.figure(figsize=(10, 7))
plt.plot(lstm_model.history_lstm.history['loss'], label='LSTM')
plt.plot(cnn_model.history_cnn.history['loss'], label='CNN')
plt.legend()
plt.xlabel('Epoch')
plt.ylabel('Loss')

plt.savefig(RESULT_PATH + "epoch_loss.png")

print("Epoch-loss graph saved.")

