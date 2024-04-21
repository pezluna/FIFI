from sklearn.ensemble import VotingClassifier, RandomForestClassifier
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten, Dropout, BatchNormalization
from xgboost import XGBClassifier
import numpy as np
from collections import Counter

embedding = {
    "Philips Hue White": 0,
    "SmartThings Smart Bulb": 1,
    "Aeotec Button": 2,
    "AeoTec Motion Sensor": 3,
    "AeoTec Multipurpose Sensor": 4,
    "AeoTec Water Leak Sensor": 5,
    "Sengled Smart Plug": 6,
    "SmartThings Button": 7,
    "SmartThings Smart Bulb": 8,
    "Sonoff Smart Plug": 9,
    "benign": 0,
    "mirai": 1,
    "qbot": 2,
    "kaiten": 3
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
            if mode == 'fingerprint':
                self.model = Sequential([
                    Conv1D(filters=16, kernel_size=3, activation='relu', input_shape=(8, 5)),
                    BatchNormalization(),
                    MaxPooling1D(pool_size=2),
                    Flatten(),
                    Dropout(0.2),
                    Dense(10, activation='softmax')
                ])
            else:
                self.model = Sequential([
                    Conv1D(filters=16, kernel_size=3, activation='relu', input_shape=(8, 5)),
                    BatchNormalization(),
                    MaxPooling1D(pool_size=2),
                    Flatten(),
                    Dense(10, activation='relu'),
                    Dropout(0.2),
                    Dense(4, activation='softmax')
                ])
        else:
            raise Exception("Invalid model type.")

    def preprocess(self, X):
        tmp = []
        for x in X:
            try:
                tmp.append(x[0][1])
            except:
                tmp.append(x[1])
        X = tmp

        return X

    def normalize(self, X):
        X = transpose(X)
        for i in range(len(X["deltaTime"])):
            if len(X["deltaTime"][i]) < 8:
                X["deltaTime"][i] += [0] * (8 - len(X["deltaTime"][i]))
        return {
            "rawLength": np.minimum(np.array(X["rawLength"]) * 0.001, 1),
            "capturedLength": np.minimum(np.array(X["capturedLength"]) * 0.001, 1),
            "direction": np.where(np.array(X["direction"]) == -1, 0, 1),
            "deltaTime": np.minimum(np.array(X["deltaTime"]) * 0.5, 1),
            "protocol": np.where(np.array(X["protocol"]) == "TCP/IP", 1, 0)
        }
    
    def train(self, X_train, y_train, X_test):
        X_train_preprocessed = self.preprocess(X_train)
        X_test_preprocessed = self.preprocess(X_test)

        X_train_normalized = self.normalize(X_train_preprocessed)
        X_test_normalized = self.normalize(X_test_preprocessed)

        indices = []
        tmp = 1 if self.mode == 'botnet' else 0

        for i, x in enumerate(X_train_normalized["protocol"]):
            if x.any() == tmp:
                indices.append(i)

        # filter_protocol = 1 if self.mode == 'botnet' else 0
        # indices = [i for i, val in enumerate(X_train_preprocessed) if val['protocol'] == filter_protocol]

        X_train_filtered = {key: X_train_normalized[key][indices] for key in X_train_normalized}
        y_train_filtered = np.array([embedding[y_train[i]] for i in indices])

        if len(y_train_filtered) == 0:
            print(indices)
            raise Exception("No data found for the given mode. Please check the mode and try again.")
        
        class_distribution = Counter(y_train_filtered)
        print("Class distribution: ", class_distribution)

        X_train_final = np.array([X_train_filtered[key] for key in ['rawLength', 'capturedLength', 'direction', 'deltaTime', 'protocol']]).transpose((1, 2, 0))

        self.model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['categorical_accuracy'])
        self.model.fit(X_train_final, y_train_filtered, epochs=25)
        
        return self.model.predict(X_test_normalized)

class StatsModel:
    def __init__(self, model = 'rf'):
        if model == 'rf':
            self.model = RandomForestClassifier()
        elif model == 'xgb':
            self.model = XGBClassifier()
        else:
            raise Exception("Invalid model type.")