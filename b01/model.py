from sklearn.ensemble import VotingClassifier, RandomForestClassifier
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten
from xgboost import XGBClassifier
import numpy as np

def transpose(X):
    transposed_data = {key: [] for key in X[0]}
    for x in X:
        for key, value in x.items():
            transposed_data[key].append(value)
    return transposed_data

class PacketModel:
    def __init__(self, model = 'cnn'):
        if model == 'cnn':
            self.model = Sequential([
                Conv1D(filters=16, kernel_size=3, activation='relu', input_shape=(5, 1)),
                MaxPooling1D(pool_size=2),
                Flatten(),
                Dense(10, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
        else:
            raise Exception("Invalid model type.")
        
    def normalize(self, X):
        tmp = []
        for x in X:
            print("--------------------")
            print(x)
            print(type(x))
            try:
                tmp.append(x[0][1])
            except:
                tmp.append(x[1])
        X = tmp
        X = transpose(X)

        raw_length_normalized = np.minimum(np.array(X["rawLength"]) * 0.001, 1)
        captured_length_normalized = np.minimum(np.array(X["capturedLength"]) * 0.001, 1)
        direction_normalized = np.where(np.array(X["direction"]) == -1, 0, 1)
        delta_time_normalized = np.minimum(np.array(X["deltaTime"]) * 0.5, 2)
        protocol_normalized = np.where(np.array(X["protocol"]) == "TCP/IP", 0, 1)

        return {
            "rawLength": raw_length_normalized,
            "capturedLength": captured_length_normalized,
            "direction": direction_normalized,
            "deltaTime": delta_time_normalized,
            "protocol": protocol_normalized
        }
    
    def train(self, X_train, y_train, X_test):
        X_train_normalized = self.normalize(X_train)
        X_test_normalized = self.normalize(X_test)
        
        X_train_normalized = np.array([list(i) for i in zip(X_train_normalized["rawLength"], X_train_normalized["capturedLength"], X_train_normalized["direction"], X_train_normalized["deltaTime"], X_train_normalized["protocol"])])
        X_test_normalized = np.array([list(i) for i in zip(X_test_normalized["rawLength"], X_test_normalized["capturedLength"], X_test_normalized["direction"], X_test_normalized["deltaTime"], X_test_normalized["protocol"])])
        
        self.model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
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