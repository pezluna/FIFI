from sklearn.ensemble import VotingClassifier, RandomForestClassifier
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten
from xgboost import XGBClassifier
import numpy as np

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
    "benign": 10,
    "mirai": 11,
    "qbot": 12,
    "kaiten": 13
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
                    MaxPooling1D(pool_size=2),
                    Flatten(),
                    Dense(10, activation='relu'),
                    Dense(10, activation='softmax')
                ])
            else:
                self.model = Sequential([
                    Conv1D(filters=16, kernel_size=3, activation='relu', input_shape=(8, 5)),
                    MaxPooling1D(pool_size=2),
                    Flatten(),
                    Dense(10, activation='relu'),
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

        # Check len of deltaTime
        for i in range(len(X["deltaTime"])):
            if len(X["deltaTime"][i]) < 8:
                X["deltaTime"][i] += [0] * (8 - len(X["deltaTime"][i]))

        raw_length_normalized = np.minimum(np.array(X["rawLength"]) * 0.001, 1)
        captured_length_normalized = np.minimum(np.array(X["capturedLength"]) * 0.001, 1)
        direction_normalized = np.where(np.array(X["direction"]) == -1, 0, 1)
        delta_time_normalized = np.minimum(np.array(X["deltaTime"]) * 0.5, 1)
        protocol_normalized = np.where(np.array(X["protocol"]) == "TCP/IP", 0, 1)

        return {
            "rawLength": raw_length_normalized,
            "capturedLength": captured_length_normalized,
            "direction": direction_normalized,
            "deltaTime": delta_time_normalized,
            "protocol": protocol_normalized
        }
    
    def train(self, X_train, y_train, X_test):
        train_indices = []
        test_indices = []

        X_train = self.preprocess(X_train)
        X_test = self.preprocess(X_test)

        if self.mode == 'fingerprint':
            train_indices = [i for i, x in enumerate(X_train) if x['protocol'] == 'Zigbee']
            test_indices = [i for i, x in enumerate(X_test) if x['protocol'] == 'Zigbee']
        else:
            train_indices = [i for i, x in enumerate(X_train) if x['protocol'] == 'TCP/IP']
            test_indices = [i for i, x in enumerate(X_test) if x['protocol'] == 'TCP/IP']

        X_train = [X_train[i] for i in train_indices]
        y_train = [y_train[i] for i in train_indices]

        X_test = [X_test[i] for i in test_indices]

        X_train_normalized = self.normalize(X_train)
        X_test_normalized = self.normalize(X_test)

        X_train_normalized = np.array([X_train_normalized[key] for key in ['rawLength', 'capturedLength', 'direction', 'deltaTime', 'protocol']]).transpose((1, 2, 0))
        X_test_normalized = np.array([X_test_normalized[key] for key in ['rawLength', 'capturedLength', 'direction', 'deltaTime', 'protocol']]).transpose((1, 2, 0))

        for i in range(len(y_train)):
            y_train[i] = embedding[y_train[i]]
        
        y_train = np.array(y_train)
        
        self.model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['categorical_accuracy'])
        self.model.fit(X_train_normalized, y_train, epochs=10)
        
        return self.model.predict(X_test_normalized)

class StatsModel:
    def __init__(self, model = 'rf'):
        if model == 'rf':
            self.model = RandomForestClassifier()
        elif model == 'xgb':
            self.model = XGBClassifier()
        else:
            raise Exception("Invalid model type.")