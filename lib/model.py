import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, GRU, Conv2D, Flatten, MaxPooling2D
from tensorflow.keras.optimizers import Adam

from lib.preprocess import preprocess_for_cnn, split_data

import logging
from lib.log_conf import init_logger

logger = logging.getLogger("logger")

class Model():
    def __init__(self):
        pass

    def run(self, sessions, algorithm):
        result = {}
        for a in algorithm:
            if a == "c":
                # CNN
                arrs, labels, cnts = preprocess_for_cnn(sessions)
                X_train, X_test, y_train, y_test = split_data(arrs, labels, cnts)

                model = Sequential()
                model.add(Conv2D(filters=32, kernel_size=(2, 2), strides=(1, 1), activation='relu', input_shape=(7, 4, 1)))
                model.add(MaxPooling2D(pool_size=(2, 2)))
                model.add(Flatten())
                model.add(Dense(32, activation='relu'))
                model.add(Dense(1, activation='sigmoid'))

                model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])
                model.fit(X_train, y_train, batch_size=32, epochs=10)
                y_pred = model.predict(X_test) 
                result["cnn"] = {"pred": y_pred, "test": y_test}
            elif a == "l":
                pass
            else:
                logger.error("Invalid algorithm: %s", a)
                raise ValueError(f"Invalid algorithm: {a}")
        
        return result

    def visualize(self):
        pass