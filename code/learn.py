import numpy as np
import time
import logging
from preprocess import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, KFold
from tensorflow.keras.layers import Dense, SimpleRNN, LSTM, Dropout, Input
from tensorflow.keras.models import Sequential
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.optimizers import Adam
from kerastuner import HyperModel
from kerastuner.tuners import Hyperband
import pickle

logger = logging.getLogger("logger")

class CustomHyperModel(HyperModel):
    def __init__(self, mode, input_shape, num_classes):
        self.mode = mode
        self.input_shape = input_shape
        self.num_classes = num_classes
    
    def build(self, hp):
        model = Sequential()

        model.add(Input(shape=self.input_shape))
        
        if self.mode == "rnn":
            for i in range(hp.Int('num_layers', 1, 3)):
                model.add(SimpleRNN(
                    units = hp.Int('units', min_value=32, max_value=256, step=16),
                    activation = hp.Choice('activation', values=['relu']),
                    return_sequences = True if i < hp.Int('num_layers', 1, 3) - 1 else False
                ))
        elif self.mode == "lstm":
            for i in range(hp.Int('num_layers', 1, 3)):
                model.add(LSTM(
                    units = hp.Int('units', min_value=32, max_value=512, step=16),
                    activation = hp.Choice('activation', values=['relu'], default='relu'),
                    return_sequences = True if i < hp.Int('num_layers', 1, 3) - 1 else False
                ))
        
        model.add(Dense(self.num_classes, activation='softmax'))

        model.compile(
            optimizer = Adam(
                hp.Choice('learning_rate', values=[1e-2, 1e-3, 1e-4])
            ),
            loss = 'categorical_crossentropy',
            metrics = ['accuracy']
        )

        return model

def check_single_class(y):
    if len(np.unique(y)) == 1:
        logger.info("Only 1 class in y. Skip.")
        logger.info(f"y: {y}")
        return True
    return False

def dt_run(X, y):
    logger.info("Running Decision Tree...")

    X = np.array(X)
    y = np.array(y)

    params = {
        'max_depth': [5, 10, 15, 20, 25, 30],
        'min_samples_leaf': [2, 4, 8, 12, 16, 20],
        'min_samples_split': [2, 4, 8, 12, 16, 20],
        'max_features': ['auto', 'sqrt', 'log2']
    }

    model = GridSearchCV(RandomForestClassifier(), params, cv=5, n_jobs=-1)

    if not check_single_class(y):
        model.fit(X, y)

    return model

def rf_run(X, y):
    logger.info("Running Random Forest...")

    X = np.array(X)
    y = np.array(y)

    params = {
        'n_estimators': [200, 300, 400, 500],
        'max_depth': [5, 10, 15, 20, 25, 30],
        'min_samples_leaf': [2, 4, 6, 8, 10],
        'min_samples_split': [2, 4, 6, 8, 10],
        'max_features': ['auto', 'sqrt', 'log2']
    }

    model = GridSearchCV(RandomForestClassifier(), params, cv=5, n_jobs=-1)

    # y의 클래스가 1개일 경우
    if not check_single_class(y):
        model.fit(X, y)

    return model

def rnn_lstm_generate(X, y, mode):
    if X.shape[0] != y.shape[0]:
        logger.error("X, y shape mismatch.")
        exit(1)
    
    logger.debug(f"X shape: {X.shape}")
    logger.debug(f"y shape: {y.shape}")

    label_to_index = {label: i for i, label in enumerate(np.unique(y))}
    index_to_label = {i: label for label, i in label_to_index.items()}
    
    # y를 one-hot encoding
    unique_y = np.unique(y)
    label_map = {label: i for i, label in enumerate(unique_y)}
    y = np.array([label_map[label] for label in y])

    num_classes=len(unique_y)
    input_shape=(None, 4)

    y = to_categorical(y, num_classes=num_classes)

    kfold = KFold(n_splits=5, shuffle=True, random_state=42)
    fold_num = 1

    for train, val in kfold.split(X, y):
        logger.info(f"Fold {fold_num}...")
        train_X, train_y = X[train], y[train]
        val_X, val_y = X[val], y[val]

        # hyperparameter tuning
        hypermodel = CustomHyperModel(mode, input_shape, num_classes)
        tuner = Hyperband(
            hypermodel,
            objective='val_accuracy',
            max_epochs=30,
            factor=3,
            directory='hyperband',
            project_name=f"{mode}_{time.strftime('%Y%m%d_%H%M%S')}"
        )

        tuner.search(X, y, epochs=40, validation_data=(val_X, val_y))

        best_hypers = tuner.get_best_hyperparameters(num_trials=1)[0]

        model = tuner.hypermodel.build(best_hypers)

        model.fit(
            X,
            y,
            epochs=40,
            validation_split=0.2,
            callbacks=[
                EarlyStopping(monitor='val_loss', patience=3),
                ReduceLROnPlateau(monitor='val_loss', patience=2)
            ]
        )

        fold_num += 1

    return model

def rnn_run(X, y):
    logger.info("Running RNN...")

    return rnn_lstm_generate(X, y, "rnn")

def lstm_run(X, y):
    logger.info("Running LSTM...")

    return rnn_lstm_generate(X, y, "lstm")

def learn(flows, labels, mode, model_type):
    logger.info(f"Creating {mode} {model_type} model...")

    model_func = {
        "rf": rf_run, 
        "dt": dt_run, 
        "rnn": rnn_run,
        "lstm": lstm_run
    }
    if model_type == "rnn" or model_type == "lstm":
        X, y = extract_features(flows, labels, mode)
    else:
        X, y = extract_features_b(flows, labels, mode)

    X = np.array(X).astype(np.float32)
    y = np.array(y).astype(np.float32)

    logger.debug(f"X shape: {X.shape}")
    logger.debug(f"y shape: {y.shape}")
    
    model = model_func[model_type](X, y)

    logger.info(f"Created {mode} {model_type} model.")

    # 생성 시간을 포함한 이름으로 모델 저장
    model_name = f"{mode}_{model_type}_{time.strftime('%Y%m%d_%H%M%S')}"
    with open(f"../model/{model_name}.pkl", 'wb') as f:
        pickle.dump(model, f)
    
    logger.info(f"Saved {mode} {model_type} model as {model_name}.pkl.")

    return model