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
cnnlstm_model = PacketModel(mode=mode, model='cnnlstm')

print("Model loaded.")

# Train the model
print("Training the model...")

packet_X_train, packet_y_train, packet_X_test = cnn_model.preprocess(X_train, y_train, X_test)

lstm_model.model.fit(packet_X_train, packet_y_train, epochs=50, batch_size=8)
cnn_model.model.fit(packet_X_train, packet_y_train, epochs=50, batch_size=8)
cnnlstm_model.model.fit(packet_X_train, packet_y_train, epochs=50, batch_size=8)

print("Training completed.")

# Evaluate the model
print("Evaluating the model...")

predictions_lstm = lstm_model.model.predict(packet_X_test)
predictions_cnn = cnn_model.model.predict(packet_X_test)
predictions_cnnlstm = cnnlstm_model.model.predict(packet_X_test)

final_y_test = []

for y in y_test:
    if y == "benign" or y == "mirai" or y == "qbot" or y == "kaiten":
        final_y_test.append(embedding_botnet[y])
    else:
        pass

final_y_test = np.array(final_y_test)
final_predictions_cnn = []
final_predictions_lstm = []
final_predictions_cnnlstm = []

# Find best threshold
from sklearn.metrics import roc_curve

cnn_best_threshold = 0
lstm_best_threshold = 0
cnnlstm_best_threshold = 0

cnn_fpr, cnn_tpr, cnn_thresholds = roc_curve(final_y_test, predictions_cnn)
lstm_fpr, lstm_tpr, lstm_thresholds = roc_curve(final_y_test, predictions_lstm)
cnnlstm_fpr, cnnlstm_tpr, cnnlstm_thresholds = roc_curve(final_y_test, predictions_cnnlstm)

cnn_gmeans = np.sqrt(cnn_tpr * (1-cnn_fpr))
lstm_gmeans = np.sqrt(lstm_tpr * (1-lstm_fpr))
cnnlstm_gmeans = np.sqrt(cnnlstm_tpr * (1-cnnlstm_fpr))

cnn_ix = np.argmax(cnn_gmeans)
lstm_ix = np.argmax(lstm_gmeans)
cnnlstm_ix = np.argmax(cnnlstm_gmeans)

cnn_best_threshold = cnn_thresholds[cnn_ix]
lstm_best_threshold = lstm_thresholds[lstm_ix]
cnnlstm_best_threshold = cnnlstm_thresholds[cnnlstm_ix]

print("Best Threshold for CNN: ", cnn_best_threshold)
print("Best Threshold for LSTM: ", lstm_best_threshold)
print("Best Threshold for CNNLSTM: ", cnnlstm_best_threshold)

# save ROC curve
import matplotlib.pyplot as plt

plt.plot(cnn_fpr, cnn_tpr, label='CNN')
plt.plot(lstm_fpr, lstm_tpr, label='LSTM')
plt.plot(cnnlstm_fpr, cnnlstm_tpr, label='CNNLSTM')

plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')

plt.legend()
plt.savefig('roc_curve.png')

print("ROC curve saved.")

for prediction in predictions_cnn:
    if prediction >= cnn_best_threshold:
        final_predictions_cnn.append(1)
    else:
        final_predictions_cnn.append(0)

for prediction in predictions_lstm:
    if prediction >= lstm_best_threshold:
        final_predictions_lstm.append(1)
    else:
        final_predictions_lstm.append(0)

for prediction in predictions_cnnlstm:
    if prediction >= cnnlstm_best_threshold:
        final_predictions_cnnlstm.append(1)
    else:
        final_predictions_cnnlstm.append(0) 


print("-------------------")
print("CNN")
print("Accuracy: ", accuracy_score(final_y_test, final_predictions_cnn))
print("Precision: ", precision_score(final_y_test, final_predictions_cnn))
print("Recall: ", recall_score(final_y_test, final_predictions_cnn))
print("F1: ", f1_score(final_y_test, final_predictions_cnn))

print("-------------------")
print("LSTM")
print("Accuracy: ", accuracy_score(final_y_test, final_predictions_lstm))
print("Precision: ", precision_score(final_y_test, final_predictions_lstm))
print("Recall: ", recall_score(final_y_test, final_predictions_lstm))
print("F1: ", f1_score(final_y_test, final_predictions_lstm))

print("-------------------")
print("CNNLSTM")
print("Accuracy: ", accuracy_score(final_y_test, final_predictions_cnnlstm))
print("Precision: ", precision_score(final_y_test, final_predictions_cnnlstm))
print("Recall: ", recall_score(final_y_test, final_predictions_cnnlstm))
print("F1: ", f1_score(final_y_test, final_predictions_cnnlstm))

print("Evaluation completed.")

# roc curve
from sklearn.metrics import roc_curve
import matplotlib.pyplot as plt

fpr_cnn, tpr_cnn, _ = roc_curve(final_y_test, final_predictions_cnn)
fpr_lstm, tpr_lstm, _ = roc_curve(final_y_test, final_predictions_lstm)
fpr_cnnlstm, tpr_cnnlstm, _ = roc_curve(final_y_test, final_predictions_cnnlstm)

plt.plot(fpr_cnn, tpr_cnn, label='CNN')
plt.plot(fpr_lstm, tpr_lstm, label='LSTM')
plt.plot(fpr_cnnlstm, tpr_cnnlstm, label='CNNLSTM')

plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')

plt.legend()
plt.savefig('roc_curve.png')

print("ROC curve saved.")
