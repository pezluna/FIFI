from sklearn.ensemble import RandomForestClassifier
from sklearn.base import BaseEstimator, ClassifierMixin
from keras.models import Sequential
from keras.layers import Dense, Conv1D, Flatten, LSTM, Input, Dropout
from xgboost import XGBClassifier
import numpy as np

embedding_botnet = {
    "benign": 0,
    "mirai": 1,
    "qbot": 2,
    "kaiten": 3
}
embedding_fingerprint = {
    "Philips Hue White": 0,
    "SmartThings Smart Bulb": 1,
    "Aeotec Button": 2,
    "AeoTec Motion Sensor": 3,
    "AeoTec Multipurpose Sensor": 4,
    "AeoTec Water Leak Sensor": 5,
    "Sengled Smart Plug": 6,
    "SmartThings Button": 7,
    "Sonoff Smart Plug": 8,
    "Aqara Door Sensor": 9,
    "Aqara Switch": 10,
    "Aqara Temperature/Humidity Sensor": 11,
    "SmartThings Multipurpose Sensor": 12
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
        self.history_lstm = None
        self.history_cnn = None
        
        if model == 'cnn':
            num_classes = 4 if mode == 'botnet' else 13
            self.model = Sequential([
                Input(shape=(8, 5)),
                Conv1D(filters=32, kernel_size=3, activation='relu'),
                Flatten(),
                Dense(64, activation='relu'),
                Dropout(0.3),
                Dense(32, activation='relu'),
                Dense(16, activation='relu'),
                Dense(num_classes, activation='softmax')
            ])
            self.model.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
        elif model == 'lstm':
            num_classes = 4 if mode == 'botnet' else 13
            self.model = Sequential([
                Input(shape=(8, 5)),
                LSTM(8),
                Dense(32, activation='relu'),
                Dropout(0.3),
                Dense(16, activation='relu'),
                Dense(num_classes, activation='softmax')
            ])
            self.model.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
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
    
    def preprocess(self, X_train, y_train, X_test):
        X_train_preprocessed = self.rearrange(X_train)
        X_test_preprocessed = self.rearrange(X_test)

        X_train_normalized = self.normalize(X_train_preprocessed)
        X_test_normalized = self.normalize(X_test_preprocessed)

        indices = []
        tmp = 1 if self.mode == 'botnet' else 0

        for i, x in enumerate(X_train_normalized["protocol"]):
            if x.all() == tmp:
                indices.append(i)

        print("train packet protocol:", len(X_train_normalized["protocol"]))
        print("train packet indices:", len(indices))

        X_train_filtered = {key: X_train_normalized[key][indices] for key in X_train_normalized}
        # y_train_filtered = np.array([embedding[y_train[i]] for i in indices])
        try:
            if self.mode == 'botnet':
                y_train_filtered = np.array([embedding_botnet[y_train[i]] for i in indices])
            else:
                y_train_filtered = np.array([embedding_fingerprint[y_train[i]] for i in indices])
        except:
            print("y_train:", y_train)
            raise Exception("Invalid y_train data. Check the data.")

        if len(y_train_filtered) == 0:
            print("No data found for the given mode. Check the mode and data.")
            return

        indices = []        
        for i, x in enumerate(X_test_normalized["protocol"]):
            if x.all() == tmp:
                indices.append(i)

        print("test packet protocol:", len(X_test_normalized["protocol"]))
        print("test packet indices:", len(indices))

        X_test_filtered = {key: X_test_normalized[key][indices] for key in X_test_normalized}
        
        X_train_final = np.stack([np.array(X_train_filtered[key]) for key in X_train_filtered], axis=-1)
        X_test_final = np.stack([np.array(X_test_filtered[key]) for key in X_test_filtered], axis=-1)
        
        return X_train_final, y_train_filtered, X_test_final

class StatsModel:
    def __init__(self, mode, model='rf'):
        self.mode = mode
        if model == 'rf':
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                class_weight='balanced'
            )
        elif model == 'xgb':
            self.model = XGBClassifier(
                n_estimators=100,
                objective='multi:softmax',
                num_class=4 if mode == 'botnet' else 13,
            )
        else:
            raise Exception("Invalid model type.")
        
    def rearrange(self, X):
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
    
    def preprocess(self, X_train, y_train, X_test):
        X_train_preprocessed = self.rearrange(X_train)
        X_test_preprocessed = self.rearrange(X_test)

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
        
        print("train stats protocol:", len(protocol))
        print("train stats indices:", len(indices))

        X_train_filtered = {key: X_train_normalized[key][indices] for key in X_train_normalized}

        if self.mode == 'botnet':
            y_train_filtered = np.array([embedding_botnet[y_train[i]] for i in indices])
        else:
            y_train_filtered = np.array([embedding_fingerprint[y_train[i]] for i in indices])

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

        print("test stats protocol:", len(protocol))
        print("test stats indices:", len(indices))

        X_test_filtered = {key: X_test_normalized[key][indices] for key in X_test_normalized}

        if len(y_train_filtered) == 0:
            print("No data found for the given mode. Check the mode and data.")
            return
        
        X_train_final = np.array([X_train_filtered[key] for key in X_train_filtered]).transpose()
        X_test_final = np.array([X_test_filtered[key] for key in X_test_filtered]).transpose()

        return X_train_final, y_train_filtered, X_test_final

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
        
        final_probs = (packet_probs + stats_probs) / 2

        # 확률이 가장 높은 클래스를 예측값으로 반환합니다.
        final_predictions = np.argmax(final_probs, axis=1)

        return final_predictions
    
    def predict_proba(self, X):
        # 각 모델의 예측 확률을 가져옵니다.
        packet_probs = self.models['packet'].predict_proba(X['packet'])
        stats_probs = self.models['stats'].predict_proba(X['stats'])

        # 예측 확률을 평균냅니다.
        final_probs = (packet_probs + stats_probs) / 2
        return final_probs