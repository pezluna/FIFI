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

        y_train_filtered = np.array([embedding_botnet[y_train[i]] for i in indices])

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