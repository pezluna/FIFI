from sklearn.ensemble import VotingClassifier, RandomForestClassifier
from xgboost import XGBClassifier

class HeaderModel:
    pass

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
        x_train, y_train, x_test, y_test = sessions.get_train_test_data()

        self.model.fit(x_train, y_train)
        pred_y = self.model.predict(x_test)

        return pred_y

    def save(self):
        pass