from sklearn.ensemble import VotingClassifier, RandomForestClassifier
from xgboost import XGBClassifier

class HeaderModel:
    def __init__(self, model = 'rf'):
        if model == 'rf':
            self.model = RandomForestClassifier()
        elif model == 'xgb':
            self.model = XGBClassifier()
        else:
            raise Exception("Invalid model type.")
        
    def train(self, sessions, labels):
        x_train, y_train, x_test, y_test = sessions.get_train_test_data()

        self.model.fit(x_train, y_train)
        pred_y = self.model.predict(x_test)

        return pred_y

class StatsModel:
    def __init__(self, model = 'rf'):
        if model == 'rf':
            self.model = RandomForestClassifier()
        elif model == 'xgb':
            self.model = XGBClassifier()
        else:
            raise Exception("Invalid model type.")
        
    def train(self, sessions, labels):
        x_train, y_train, x_test, y_test = sessions.get_train_test_data()

        self.model.fit(x_train, y_train)
        pred_y = self.model.predict(x_test)

        return pred_y

class EnsembleModel:
    def __init__(self, branch_1, branch_2, voting = 'soft'):
        self.model = VotingClassifier(
            estimators = [
                ('header', branch_1.model),
                ('stats', branch_2.model)
            ],
            voting = voting
        )

    def train(self, sessions):
        X_train, y_train, X_test, y_test = sessions.get_train_test_data()

        # Validate the data
        if len(X_train) != len(y_train):
            raise Exception("Invalid data. X_train and y_train should have the same length.")
        if len(X_test) != len(y_test):
            raise Exception("Invalid data. X_test and y_test should have the same length.")
        
        self.model.fit(X_train, y_train)
        pred_y = self.model.predict(X_test)

        return pred_y

    def save(self):
        pass