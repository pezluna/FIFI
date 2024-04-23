from sklearn.ensemble import RandomForestClassifier
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.utils.class_weight import compute_class_weight
from keras.models import Sequential
from keras.layers import Dense, Conv1D, Flatten, Dropout, BatchNormalization, LSTM
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
    "Sonoff Smart Plug": 8,
    "Aqara Door Sensor": 9,
    "Aqara Switch": 10,
    "Aqara Temperature/Humidity Sensor": 11,
    "SmartThings Multipurpose Sensor": 12,
    "benign": 0,
    "mirai": 1,
    "qbot": 2,
    "kaiten": 3
}

class_weights = compute_class_weight(
    'balanced',
    np.unique(list(embedding.values())),
    list(embedding.values())
)

class_weights_dict = {i: class_weights[i] for i in range(len(class_weights))}

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
            num_classes = 4 if mode == 'botnet' else 13
            self.model = Sequential([
                Conv1D(filters=32, kernel_size=3, activation='relu', input_shape=(8, 5)),
                BatchNormalization(),
                Flatten(),
                Dense(64, activation='relu'),
                Dropout(0.2),
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
                LSTM(32, input_shape=(8, 5)),
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
        y_train_filtered = np.array([embedding[y_train[i]] for i in indices])

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
                n_estimators=300,
                max_depth=10,
                verbose=1,
                class_weight=class_weights_dict
            )
        elif model == 'xgb':
            self.model = XGBClassifier(
                n_estimators=300,
                max_depth=10,
                verbosity=1,
                objective='multi:softmax',
                num_class=4 if mode == 'botnet' else 13,
                scale_pos_weight=class_weights_dict
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

        print("test stats protocol:", len(protocol))
        print("test stats indices:", len(indices))

        X_test_filtered = {key: X_test_normalized[key][indices] for key in X_test_normalized}

        if len(y_train_filtered) == 0:
            print("No data found for the given mode. Check the mode and data.")
            return
        
        X_train_final = np.array([X_train_filtered[key] for key in X_train_filtered]).transpose()
        X_test_final = np.array([X_test_filtered[key] for key in X_test_filtered]).transpose()

        return X_train_final, y_train_filtered, X_test_final
    
# class EnsembleClassifier(BaseEstimator, ClassifierMixin):
#     def __init__(self, models, mode):
#         self.models = models
#         self.mode = mode
#         self.num_classes = 4 if mode == 'botnet' else 13
    
#     def fit(self, X, y):
#         # 각 모델에 대한 데이터와 타깃을 받아 모델 별로 학습을 수행
#         self.models['packet'].fit(X['packet'], y)
#         self.models['stats'].fit(X['stats'], y)
#         return self
    
#     def predict(self, X):
#         # 차원 확인
#         print("Packet data shape:", X['packet'].shape)
#         print("Stats data shape:", X['stats'].shape)
#         if len(X['packet']) != len(X['stats']):
#             raise ValueError("Different number of samples in packet and stats data.")

#         # 각 모델에서 확률 예측을 수행
#         packet_predictions = self.models['packet'].predict(X['packet'])
#         stats_predictions = self.models['stats'].predict_proba(X['stats'])

#         # 차원 확인
#         print("Packet predictions shape:", packet_predictions.shape)
#         print("Stats predictions shape:", stats_predictions.shape)

#         final_predictions = self.calculate_final_predictions(packet_predictions, stats_predictions)

#         final_predictions = np.array(final_predictions)

#         return final_predictions
    
#     def calculate_final_predictions(self, packet_probs, stats_probs):
#         final_predictions = []
#         for packet_prob, stats_prob in zip(packet_probs, stats_probs):
#             # 패킷 모델과 통계 모델의 예측 확률을 각각 평가합니다.
#             packet_label = np.argmax(packet_prob)
#             stats_label = np.argmax(stats_prob)

#             # 두 모델이 동일한 레이블을 예측했다면, 해당 레이블을 선택합니다.
#             if packet_label == stats_label:
#                 final_predictions.append(packet_label)
#             else:
#                 # 두 모델이 서로 다른 레이블을 예측했다면, 각 레이블의 평균 확률을 비교하여 더 높은 확률을 가진 레이블을 선택합니다.
#                 packet_label_prob = packet_prob[packet_label]
#                 stats_label_prob = stats_prob[stats_label]
#                 if packet_label_prob > stats_label_prob:
#                     final_predictions.append(packet_label)
#                 else:
#                     final_predictions.append(stats_label)
#         return final_predictions

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