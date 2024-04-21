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
            num_classes = 4 if mode == 'botnet' else 10
            self.model = Sequential([
                Conv1D(filters=32, kernel_size=3, activation='relu', input_shape=(8, 5)),
                BatchNormalization(),
                MaxPooling1D(pool_size=2),
                Conv1D(filters=64, kernel_size=3, activation='relu'),
                Flatten(),
                Dense(64, activation='relu'),
                Dropout(0.5),
                Dense(num_classes, activation='softmax')
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
            if x.all() == tmp:
                indices.append(i)

        X_train_filtered = {key: X_train_normalized[key][indices] for key in X_train_normalized}
        y_train_filtered = np.array([embedding[y_train[i]] for i in indices])

        if len(y_train_filtered) == 0:
            print("No data found for the given mode. Check the mode and data.")
            return

        X_train_final = np.array([X_train_filtered[key] for key in ['rawLength', 'capturedLength', 'direction', 'deltaTime', 'protocol']]).transpose((1, 2, 0))
        X_test_final = np.array([X_test_normalized[key] for key in ['rawLength', 'capturedLength', 'direction', 'deltaTime', 'protocol']]).transpose((1, 2, 0))

        self.model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['categorical_accuracy'])
        self.model.fit(X_train_final, y_train_filtered, epochs=50)
        
        return self.model.predict(X_test_final)

class StatsModel:
    def __init__(self, mode, model='rf'):
        self.mode = mode
        if model == 'rf':
            self.model = RandomForestClassifier()
        elif model == 'xgb':
            self.model = XGBClassifier()
        else:
            raise Exception("Invalid model type.")
        
    def preprocess(self, X):
        tmp = []
        for x in X:
            try:
                tmp.append(x[0][0])
            except:
                tmp.append(x[0])
        X = tmp

        return X
    
    def normalize(self, X):
        X = transpose(X)
        return {
            "sPackets": np.array(X["sPackets"]),
            "rPackets": np.array(X["rPackets"]),
            "sTotalSize": np.array(X["sTotalSize"]),
            "rTotalSize": np.array(X["rTotalSize"]),
            "sMinSize": np.array(X["sMinSize"]),
            "rMinSize": np.array(X["rMinSize"]),
            "sMaxSize": np.array(X["sMaxSize"]),
            "rMaxSize": np.array(X["rMaxSize"]),
            "sAvgSize": np.array(X["sAvgSize"]),
            "rAvgSize": np.array(X["rAvgSize"]),
            "sVarSize": np.array(X["sVarSize"]),
            "rVarSize": np.array(X["rVarSize"]),
            "sMinInterval": np.array(X["sMinInterval"]),
            "rMinInterval": np.array(X["rMinInterval"]),
            "sMaxInterval": np.array(X["sMaxInterval"]),
            "rMaxInterval": np.array(X["rMaxInterval"]),
            "sAvgInterval": np.array(X["sAvgInterval"]),
            "rAvgInterval": np.array(X["rAvgInterval"]),
            "sVarInterval": np.array(X["sVarInterval"]),
            "rVarInterval": np.array(X["rVarInterval"]),
            "sRatio": np.array(X["sRatio"]),
        }
    
    def check_NaN(self, X):
        for x in X:
            for key, value in x.items():
                if value is None:
                    if key != "sRatio":
                        x[key] = 0
                    else:
                        x[key] = 1 if x["sPackets"] > 0 else 0
        
        return X

    
    def train(self, X_train, y_train, X_test):
        X_train_preprocessed = self.preprocess(X_train)
        X_test_preprocessed = self.preprocess(X_test)

        # 결측치 처리
        X_train_without_NaN = self.check_NaN(X_train_preprocessed)
        X_test_without_NaN = self.check_NaN(X_test_preprocessed)

        X_train_normalized = self.normalize(X_train_without_NaN)
        X_test_normalized = self.normalize(X_test_without_NaN)

        tmp = "TCP/IP" if self.mode == 'botnet' else "Zigbee"
        indices = []

        protocol = []
        for x in X_train:
            try:
                protocol.append(x[0][1]["protocol"])
            except:
                protocol.append(x[1]["protocol"])

        for i, x in enumerate(protocol):
            if tmp in x:
                indices.append(i)


        X_train_filtered = {key: X_train_normalized[key][indices] for key in X_train_normalized}
        y_train_filtered = np.array([embedding[y_train[i]] for i in indices])

        protocol = []
        for x in X_test:
            try:
                protocol.append(x[0][1]["protocol"])
            except:
                protocol.append(x[1]["protocol"])

        indices = []
        for i, x in enumerate(protocol):
            if tmp in x:
                indices.append(i)

        X_test_filtered = {key: X_test_normalized[key][indices] for key in X_test_normalized}

        if len(y_train_filtered) == 0:
            print("No data found for the given mode. Check the mode and data.")
            return
        
        X_train_final = np.array([X_train_filtered[key] for key in X_train_filtered]).transpose()
        X_test_final = np.array([X_test_filtered[key] for key in X_test_filtered]).transpose()

        self.model.fit(X_train_final, y_train_filtered)
        return self.model.predict(X_test_final)
    
    # def train(self, X_train, y_train, X_test):
    #     X_train_preprocessed = self.preprocess(X_train)
    #     X_test_preprocessed = self.preprocess(X_test)

    #     protocol = []
    #     for x in X_train:
    #         try:
    #             protocol.append(x[0][1]["protocol"])
    #         except:
    #             protocol.append(x[1]["protocol"])

    #     X_train_normalized = self.normalize(X_train_preprocessed)
    #     X_test_normalized = self.normalize(X_test_preprocessed)

    #     indices = []
    #     tmp = "TCP/IP" if self.mode == 'botnet' else "Zigbee"
        
    #     for i, x in enumerate(protocol):
    #         if tmp in x:
    #             indices.append(i)

    #     X_train_filtered = {key: np.array(X_train_normalized[key])[indices] for key in X_train_normalized}
    #     X_test_filtered = {key: np.array(X_test_normalized[key])[indices] for key in X_test_normalized}

    #     # 차원 추가 및 확인
    #     for key in X_train_filtered:
    #         if X_train_filtered[key].ndim == 1:
    #             X_train_filtered[key] = np.expand_dims(X_train_filtered[key], axis=1)
    #         if X_test_filtered[key].ndim == 1:
    #             X_test_filtered[key] = np.expand_dims(X_test_filtered[key], axis=1)
    #         print(f"{key} train shape: {X_train_filtered[key].shape}, test shape: {X_test_filtered[key].shape}")

    #     y_train_filtered = np.array([embedding[y_train[i]] for i in indices])

    #     if len(y_train_filtered) == 0:
    #         print("No data found for the given mode. Check the mode and data.")
    #         return

    #     # 데이터 연결
    #     try:
    #         X_train_final = np.concatenate([X_train_filtered[key] for key in X_train_filtered], axis=1)
    #         X_test_final = np.concatenate([X_test_filtered[key] for key in X_test_filtered], axis=1)
    #     except Exception as e:
    #         print(f"Error in concatenation: {str(e)}")
    #         return

    #     self.model.fit(X_train_final, y_train_filtered)
    #     return self.model.predict(X_test_final)