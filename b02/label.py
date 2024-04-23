import sys
import os

class Label:
    def __init__(self):
        self.label_path = "./label/"
        self.label = {
            "label": [],
            "id": [],
            "remarks": [],
            "protocol": []
        }

    def load(self):
        if os.path.exists(self.label_path + "label.csv"):
            with open(os.path.join(self.label_path, "label.csv")) as f:
                for i, line in enumerate(f):
                    if i == 0:
                        # header
                        continue

                    line = line.strip().split(",")

                    self.label["label"].append(line[0].strip())
                    self.label["id"].append(line[1].strip())
                    self.label["remarks"].append(line[2].strip())
                    self.label["protocol"].append(line[3].strip())