import sys
import os
import json
import numpy as np
import pyshark
from datetime import datetime

from label import Label

class Session:
    def __init__(self, metadata, packet, label):
        self.metadata = metadata
        self.packet = [packet]
        self.label = label
    
    def to_dict(self):
        return {
            "metadata": self.metadata,
            "packet": self.packet,
            "label": self.label
        }

class Sessions:
    def __init__(self):
        self.sessions_path = "./sessions/"
        # self.zigbee_raw_path = "./raw/zigbee/"
        self.cnc_raw_path = "./raw/cnc/"
        self.sessions = {
            "session": [],
            "train": [],
            "test": []
        }

    def reset(self):
        if os.path.exists(self.sessions_path + "sessions.json"):
            os.remove(self.sessions_path + "sessions.json")
        
        self.load()
    
    def load(self):
        if os.path.exists(self.sessions_path + "sessions.json"):
            with open(os.path.join(self.sessions_path, "sessions.json")) as f:
                data = json.load(f)
                self.sessions = data
        else:
            self.make()
            self.save()

    def make(self):
        for file in os.listdir(self.cnc_raw_path):
            if file.endswith(".csv"):
                print("Processing " + file + "...")

                with open(os.path.join(self.cnc_raw_path, file)) as f:
                    metadatas, packetDatas = self.get_cnc_data(f)
                    for i, metadata in enumerate(metadatas):
                        reverse_metadata = {
                            "srcId": metadata["dstId"],
                            "dstId": metadata["srcId"],
                            "protocol": metadata["protocol"],
                            "remarks": metadata["remarks"]
                        }

                        for j in range(len(self.sessions["session"])):
                            if metadata == self.sessions["session"][j].metadata or reverse_metadata == self.sessions["session"][j].metadata:
                                self.sessions["session"][j].packet.append(packetDatas[i])
                                break
                        else:
                            if "benign" in file:
                                l = "benign"
                            elif "mirai" in file:
                                l = "mirai"
                            elif "qbot" in file:
                                l = "qbot"
                            elif "kaiten" in file:
                                l = "kaiten"
                            else:
                                raise Exception("Invalid file name")
                            
                            self.sessions["session"].append(Session(metadata, packetDatas[i], l))
                    
    def save(self, filename="sessions.json"):
        session_data = [session.to_dict() for session in self.sessions["session"]]
        try:
            with open(os.path.join(self.sessions_path, filename), "w") as f:
                json.dump({"session": session_data, "train":self.sessions["train"], "test":self.sessions["test"]}, f, indent=4)
        except:
            print("Error saving session data.")
            raise Exception("Error saving session data.")
    
    def get_cnc_data(self, csv):
        metadatas = []
        statisticsDatas = []
        packetDatas = []
        for i, line in enumerate(csv):
            if i > 10:
                break
            if i == 0:
                # header
                continue

            if i % 10 == 0:
                print("Processing line " + str(i) + "...")
            metadata = {
                "srcId": None,
                "dstId": None,
                "protocol": None,
                "remarks": None
            }
            packetData = {
                "rawTime": [],
                "rawLength": [],
                "payload": [],
                "capturedLength": [],
                "direction": [],
                "deltaTime": [],
                "protocol": []
            }

            last_sTime = None
            last_rTime = None
            
            s_lengths = []
            r_lengths = []
            s_intervals = []
            r_intervals = []

            line = line.strip().split(",")

            metadata["dstId"] = line[0].strip()
            metadata["srcId"] = line[1].strip()
            metadata["protocol"] = "TCP/IP"
            metadata["remarks"] = (line[11].strip(), line[12].strip())

            directions = line[17].strip()
            flags = line[18].strip()
            lengths = line[19].strip()
            times = line[20].strip()

            directions = list(map(int, directions[1:-1].split("|")))
            flags = list(map(int, flags[1:-1].split("|")))
            lengths = list(map(int, lengths[1:-1].split("|")))
            times = times[1:-1].split("|")

            for i in range(len(directions)):
                direction = directions[i]
                length = lengths[i]
                time = datetime.fromisoformat(times[i]).timestamp()

                if direction == 1:
                    s_lengths.append(length)

                    if last_sTime is not None:
                        interval = time - last_sTime
                        s_intervals.append(interval)
                        packetData["deltaTime"].append(interval)
                    else:
                        pass
                    last_sTime = time
                else:
                    r_lengths.append(length)

                    if last_rTime is not None:
                        interval = time - last_rTime
                        r_intervals.append(interval)
                        packetData["deltaTime"].append(interval)
                    else:
                        pass
                    last_rTime = time

                packetData["rawTime"].append(time)
                packetData["rawLength"].append(length)
                packetData["capturedLength"].append(length)
                packetData["direction"].append(direction)
                packetData["payload"].append(None)
                packetData["protocol"].append("TCP/IP")

            packetData["deltaTime"] = [0] + packetData["deltaTime"]
            packetData["direction"] = packetData["direction"][:8]
            packetData["protocol"] = packetData["protocol"][:8]
            packetData["rawLength"] = packetData["rawLength"][:8]
            packetData["capturedLength"] = packetData["capturedLength"][:8]
            packetData["deltaTime"] = packetData["deltaTime"][:8]

            if len(packetData["protocol"]) < 8:
                packetData["direction"].extend([1] * (8 - len(packetData["direction"])))
                packetData["protocol"].extend(["TCP/IP"] * (8 - len(packetData["protocol"])))
                packetData["rawLength"].extend([0] * (8 - len(packetData["rawLength"])))
                packetData["capturedLength"].extend([0] * (8 - len(packetData["capturedLength"])))
                packetData["deltaTime"].extend([0] * (8 - len(packetData["deltaTime"])))

            metadatas.append(metadata)
            packetDatas.append(packetData)

            print("Metadata: ", metadata)
            print("Packet Data: ", packetData)
            input()

        return metadatas, packetDatas
    
    def split_train_test(self):
        # Splitting the data into train and test, 60% train and 40% test
        train = {"packet": [], "label": []}
        test = {"packet": [], "label": []}
        labels = []

        for i, session in enumerate(self.sessions["session"]):
            # print("Processing session " + str(i) + "...")

            metadata = session["metadata"]
            packet = session["packet"]
            label = session["label"]

            idxs = []

            if label not in labels:
                labels.append(label)

                for j, s in enumerate(self.sessions["session"]):
                    if s["label"] == label:
                        idxs.append(j)

                train_idxs = np.random.choice(idxs, round(len(idxs)*0.5), replace=False)
                test_idxs = [j for j in idxs if j not in train_idxs]

                for idx in train_idxs:
                    train["packet"].append(self.sessions["session"][idx]["packet"])
                    train["label"].append(label)

                for idx in test_idxs:
                    test["packet"].append(self.sessions["session"][idx]["packet"])
                    test["label"].append(label)

            # if metadata["protocol"] == "TCP/IP":
            #     idxs = []

            #     if label not in labels:
            #         labels.append(label)

            #         for j, s in enumerate(self.sessions["session"]):
            #             if s["label"] == label:
            #                 idxs.append(j)

            #         train_idxs = np.random.choice(idxs, round(len(idxs)*0.5), replace=False)
            #         test_idxs = [j for j in idxs if j not in train_idxs]

            #         for idx in train_idxs:
            #             train["body"].append(self.sessions["session"][idx]["body"])
            #             train["label"].append(label)
            #         for idx in test_idxs:
            #             test["body"].append(self.sessions["session"][idx]["body"])
            #             test["label"].append(label)
            #     else:
            #         continue
            # else:
            #     idxs = [i for i in range(len(body))]
            #     train_idxs = np.random.choice(idxs, round(len(idxs)*0.6), replace=False)
            #     test_idxs = [i for i in idxs if i not in train_idxs]

            #     for idx in train_idxs:
            #         train["body"].append(body[idx])
            #         train["label"].append(label)
            #     for idx in test_idxs:
            #         test["body"].append(body[idx])
            #         test["label"].append(label)

        self.sessions["train"] = train
        self.sessions["test"] = test

    def get_train_test_data(self):
        x_train = []
        y_train = []
        x_test = []
        y_test = []

        for i, body in enumerate(self.sessions["train"]["packet"]):
            x_train.append(body)
            y_train.append(self.sessions["train"]["label"][i])

        for i, body in enumerate(self.sessions["test"]["packet"]):
            x_test.append(body)
            y_test.append(self.sessions["test"]["label"][i])

        return x_train, y_train, x_test, y_test