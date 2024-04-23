from sklearn.ensemble import RandomForestClassifier
from sklearn.base import BaseEstimator, ClassifierMixin
from keras.models import Sequential
from keras.layers import Dense, Conv1D, Flatten, Dropout, BatchNormalization, LSTM
from xgboost import XGBClassifier
import numpy as np

embedding_botnet = {
    "benign": 0,
    "mirai": 1,
    "qbot": 1,
    "kaiten": 1
}

def transpose(X):
    transposed_data = {key: [] for key in X[0]}
    for x in X:
        for key, value in x.items():
            transposed_data[key].append(value)
    return transposed_data

class PacketModel:
    def __init__(self, mode, model='cnn'):
        self.mode = mode
        if model == 'cnn':
            self.model = Sequential([
                Conv1D(filters=64, kernel_size=2, activation='relu', input_shape=(8, 5)),
                Flatten(),
                Dense(128, activation='relu'),
                Dropout(0.5),
                Dense(64, activation='relu'),
                Dropout(0.5),
                Dense(1, activation='sigmoid')
            ])
            self.model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
        elif model == 'lstm':
            self.model = Sequential([
                LSTM(64, input_shape=(8, 5)),
                Flatten(),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            self.model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )

    def rearrange(self, X):
        tmp = []
        for x in X:
            try:
                tmp.append(x[0][1])
            except:
                tmp.append(x[1])
        X = tmp

        return X

    def normalize(self, X):
        transposed_data = {
            "rawLength": [],
            "capturedLength": [],
            "direction": [],
            "deltaTime": [],
            "protocol": []
        }

        for x in X:
            x = x[0]
            rawLength = []
            capturedLength = []
            direction = []
            deltaTime = []
            protocol = []

            for i in range(8):
                try:
                    rawLength.append(min(x["rawLength"][i] * 0.04, 1))
                except:
                    rawLength.append(0)

                try:
                    capturedLength.append(min(x["capturedLength"][i] * 0.04, 1))
                except:
                    capturedLength.append(0)

                try:
                    direction.append(1 if x["direction"][i] == 1 else 0)
                except:
                    direction.append(0)

                try:
                    deltaTime.append(min(x["deltaTime"][i], 1))
                except:
                    deltaTime.append(0)

                try:
                    protocol.append(1 if x["protocol"][i] == "TCP/IP" else 0)
                except:
                    protocol.append(0)

            transposed_data["rawLength"].append(rawLength)
            transposed_data["capturedLength"].append(capturedLength)
            transposed_data["direction"].append(direction)
            transposed_data["deltaTime"].append(deltaTime)
            transposed_data["protocol"].append(protocol)

        return np.array(transposed_data)
    
    def preprocess(self, X_train, y_train, X_test):
        # X_train_preprocessed = self.rearrange(X_train)
        # X_test_preprocessed = self.rearrange(X_test)

        X_train_normalized = self.normalize(X_train)
        X_test_normalized = self.normalize(X_test)

        print(X_train_normalized)
        print(X_test_normalized)

        self.check_lengths(X_train_normalized)
        self.check_lengths(X_test_normalized)
        
        X_train_final = np.stack([np.array(X_train_normalized[key]) for key in X_train_normalized], axis=-1)
        X_test_final = np.stack([np.array(X_test_normalized[key]) for key in X_test_normalized], axis=-1)
        
        return X_train_final, y_train, X_test_final
    
    def check_lengths(self, data):
        lengths = {key: [] for key in data}  # Dictionary to store lengths of each list for each key
        inconsistent_lengths = {key: set() for key in data}  # Dictionary to store unique lengths that vary

        for key, values in data.items():
            for value in values:
                length = len(value)  # Get the length of each list
                lengths[key].append(length)
                inconsistent_lengths[key].add(length)  # Add length to set for uniqueness

        # Print the lengths for each key and check for inconsistencies
        for key, length_set in inconsistent_lengths.items():
            if len(length_set) > 1:  # More than one unique length indicates inconsistency
                print(f"Inconsistent lengths found in '{key}': {length_set}")
                raise ValueError(f"Inconsistent lengths found in '{key}': {length_set}")
            else:
                print(f"All lists in '{key}' are consistent with length: {list(length_set)[0]}")

        return lengths

class EnsembleClassifier(BaseEstimator, ClassifierMixin):
    def __init__(self, models, mode):
        self.models = models
        self.mode = mode
        self.num_classes = 4 if mode == 'botnet' else 13
    
    def fit(self, X, y):
        # 각 모델을 해당 데이터에 맞게 학습시킵니다.
        self.models['packet'].fit(X['packet'], y)
        self.models['stats'].fit(X['stats'], y)
        return self
    
    def predict(self, X):
        # 각 모델의 예측 확률을 가져옵니다.
        packet_probs = self.models['packet'].predict(X['packet'])
        stats_probs = self.models['stats'].predict_proba(X['stats'])

        # 예측 확률을 평균내어 최종 예측을 결정합니다.
        final_probs = (packet_probs + stats_probs) / 2
        final_predictions = np.argmax(final_probs, axis=1)

        return final_predictions
    
    def predict_proba(self, X):
        # 각 모델의 예측 확률을 가져옵니다.
        packet_probs = self.models['packet'].predict_proba(X['packet'])
        stats_probs = self.models['stats'].predict_proba(X['stats'])

        # 예측 확률을 평균냅니다.
        final_probs = (packet_probs + stats_probs) / 2
        return final_probs