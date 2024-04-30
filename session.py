import sys
import os
import json
import numpy as np
import pyshark
from datetime import datetime


from label import Label

def meta_eq(meta1, meta2):
    cond = [
        meta1["srcId"] == meta2["srcId"],
        meta1["dstId"] == meta2["dstId"],
        meta1["protocol"] == meta2["protocol"],
        meta1["remarks"] == meta2["remarks"]
    ]

    return all(cond)

class Session:
    def __init__(self, metadata, body, label):
        self.metadata = metadata
        self.body = body
        self.label = label
    
    def to_dict(self):
        return {
            "metadata": self.metadata,
            "body": self.body,
            "label": self.label
        }
    
    def to_class(self, data):
        self.metadata = data["metadata"]
        self.body = data["body"]
        self.label = data["label"]

class Sessions:
    def __init__(self):
        self.sessions_path = "./sessions/"
        self.zigbee_raw_path = "./raw/zigbee/"
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

            for session in data["session"]:
                s = Session(None, None, None)
                s.to_class(session)
                self.sessions["session"].append(s)
        else:
            self.make()
            self.save()

    def make(self):
        # Zigbee
        label = Label()
        label.load()

        for file in os.listdir(self.zigbee_raw_path):
            if file.endswith(".pcapng") or file.endswith(".pcap"):
                print("Processing " + file + "...")
                with pyshark.FileCapture(os.path.join(self.zigbee_raw_path, file), include_raw=True, use_json=True) as pcap:
                    # pcap.set_debug(True)
                    metadata = self.get_zigbee_metadata(pcap)
                    if metadata is None:
                        continue
                    bodydata = self.get_zigbee_bodydata(pcap)
                    if bodydata is None:
                        continue

                    # padding
                    if len(bodydata[1]["rawTime"]) < 8:
                        bodydata[1]["rawLength"].extend([0] * (8 - len(bodydata[1]["rawLength"])))
                        bodydata[1]["direction"].extend([1] * (8 - len(bodydata[1]["direction"])))
                        bodydata[1]["deltaTime"].extend([0] * (8 - len(bodydata[1]["deltaTime"])))
                        bodydata[1]["protocol"].extend(["Zigbee"] * (8 - len(bodydata[1]["protocol"])))
                        bodydata[1]["capturedLength"].extend([0] * (8 - len(bodydata[1]["capturedLength"])))

                    reverse_metadata = {
                        "srcId": metadata["dstId"],
                        "dstId": metadata["srcId"],
                        "protocol": metadata["protocol"],
                        "remarks": metadata["remarks"]
                    }

                    for i in range(len(self.sessions["session"])):
                        # if metadata == self.sessions["session"][i].metadata or reverse_metadata == self.sessions["session"][i].metadata:
                        if meta_eq(metadata, self.sessions["session"][i].metadata) or meta_eq(reverse_metadata, self.sessions["session"][i].metadata):
                            self.sessions["session"][i].body.append(bodydata)
                            self.sessions["session"][i].metadata["count"] += 1
                            break
                    else:
                        # map labels
                        srcId = metadata["srcId"]
                        dstId = metadata["dstId"]
                        protocol = metadata["protocol"]
                        remarks = metadata["remarks"]
                        metadata.update({"count": 1})
                        l = None

                        for j in range(len(label.label["id"])):
                            if srcId == label.label["id"][j] and protocol == label.label["protocol"][j] and remarks == label.label["remarks"][j]:
                                l = label.label["label"][j]
                                break
                            elif dstId == label.label["id"][j] and protocol == label.label["protocol"][j] and remarks == label.label["remarks"][j]:
                                l = label.label["label"][j]
                                break
                        else:
                            print("srcId: " + srcId)
                            print("dstId: " + dstId)
                            print("protocol: " + protocol)
                            print("remarks: " + remarks)
                            raise Exception("Invalid metadata.")
                        
                        self.sessions["session"].append(Session(metadata, [bodydata], l))
                        # self.sessions["session"].append(Session(metadata, [bodydata], l))


        # CNC
        for file in os.listdir(self.cnc_raw_path):
            if file.endswith(".csv"):
                print("Processing " + file + "...")

                with open(os.path.join(self.cnc_raw_path, file)) as f:
                    metadatas, statisticsDatas, packetDatas = self.get_cnc_data(f)
                    for i, metadata in enumerate(metadatas):
                        reverse_metadata = {
                            "srcId": metadata["dstId"],
                            "dstId": metadata["srcId"],
                            "protocol": metadata["protocol"],
                            "remarks": metadata["remarks"]
                        }

                        for j in range(len(self.sessions["session"])):
                            # if metadata == self.sessions["session"][j].metadata or reverse_metadata == self.sessions["session"][j].metadata:
                            if meta_eq(metadata, self.sessions["session"][j].metadata) or meta_eq(reverse_metadata, self.sessions["session"][j].metadata):
                                self.sessions["session"][j].body.append((statisticsDatas[i], packetDatas[i]))
                                print("Appended to existing session.")
                                print("Metadata: " + str(metadata))
                                print("Length: " + str(len(self.sessions["session"][j].body)))
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
                            
                            self.sessions["session"].append(Session(metadata, [(statisticsDatas[i], packetDatas[i])], l))
                    
    def save(self, filename="sessions.json"):
        session_data = [session.to_dict() for session in self.sessions["session"]]
        with open(os.path.join(self.sessions_path, filename), "w") as f:
            json.dump({"session": session_data, "train":self.sessions["train"], "test":self.sessions["test"]}, f, indent=4)

    def get_zigbee_metadata(self, pcap):
        metadata = {}

        for i, pkt in enumerate(pcap):
            if 'ZBEE_NWK' in pkt.highest_layer:
                if pkt.wpan.dst16 == "0xffff":
                    continue
                metadata["srcId"] = pkt.wpan.src16
                metadata["dstId"] = pkt.wpan.dst16
                metadata["protocol"] = "Zigbee"
                metadata["remarks"] = pkt.wpan.dst_pan

                break
        else:
            # Whole packet is broadcast
            return None

        return metadata

    def get_zigbee_bodydata(self, pcap):
        statisticsData = {
            "sPackets": None,
            "rPackets": None,
            "sTotalSize": None,
            "rTotalSize": None,
            "sMinSize": None,
            "rMinSize": None,
            "sMaxSize": None,
            "rMaxSize": None,
            "sAvgSize": None,
            "rAvgSize": None,
            "sVarSize": None,
            "rVarSize": None,
            "sMinInterval": None,
            "rMinInterval": None,
            "sMaxInterval": None,
            "rMaxInterval": None,
            "sAvgInterval": None,
            "rAvgInterval": None,
            "sVarInterval": None,
            "rVarInterval": None,
            "sRatio": None
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
        srcId = None

        i = 0

        for i, pkt in enumerate(pcap):
            if 'ZBEE_NWK' in pkt.highest_layer:
                if pkt.wpan.dst16 == "0xffff":
                    continue
                if srcId is None:
                    srcId = pkt.wpan.src16
                currentTime = float(pkt.sniff_timestamp)
                direction = 0 if srcId == pkt.wpan.src16 else 1

                if i < 8:
                    packetData["rawTime"].append(currentTime)
                    packetData["rawLength"].append(pkt.length)
                    packetData["payload"].append(pkt.get_raw_packet().decode("utf-8", errors="replace"))
                    packetData["capturedLength"].append(pkt.captured_length) if pkt.captured_length is not None else packetData["capturedLength"].append(pkt.length)
                    packetData["direction"].append(direction)
                    packetData["protocol"].append("Zigbee")

                if direction == 0:
                    s_lengths.append(pkt.length)
                    if last_sTime is not None:
                        interval = currentTime - last_sTime
                        s_intervals.append(interval)
                        if i < 8:
                            packetData["deltaTime"].append(interval)
                    else:
                        pass
                    last_sTime = currentTime
                else:
                    r_lengths.append(pkt.length)
                    if last_rTime is not None:
                        interval = currentTime - last_rTime
                        r_intervals.append(interval)
                        if i < 8:
                            packetData["deltaTime"].append(interval)
                    else:
                        pass
                    last_rTime = currentTime

        packetData["deltaTime"] = [0] + packetData["deltaTime"]

        if i == 0:
            return None

        if i < 8:
            packetData["deltaTime"].extend([0] * (8 - len(packetData["deltaTime"])))
            packetData["direction"].extend([1] * (8 - len(packetData["direction"])))
            packetData["protocol"].extend(["Zigbee"] * (8 - len(packetData["protocol"])))
            packetData["rawLength"].extend([0] * (8 - len(packetData["rawLength"])))
            packetData["capturedLength"].extend([0] * (8 - len(packetData["capturedLength"])))

        # Calculating statistics
        statisticsData["sPackets"] = len(s_lengths)
        statisticsData["rPackets"] = len(r_lengths)
        statisticsData["sTotalSize"] = sum(s_lengths)
        statisticsData["rTotalSize"] = sum(r_lengths)
        statisticsData["sMinSize"] = min(s_lengths) if s_lengths else None
        statisticsData["rMinSize"] = min(r_lengths) if r_lengths else None
        statisticsData["sMaxSize"] = max(s_lengths) if s_lengths else None
        statisticsData["rMaxSize"] = max(r_lengths) if r_lengths else None
        statisticsData["sAvgSize"] = np.mean(s_lengths) if s_lengths else None
        statisticsData["rAvgSize"] = np.mean(r_lengths) if r_lengths else None
        statisticsData["sVarSize"] = np.var(s_lengths) if s_lengths else None
        statisticsData["rVarSize"] = np.var(r_lengths) if r_lengths else None
        statisticsData["sMinInterval"] = min(s_intervals) if s_intervals else None
        statisticsData["rMinInterval"] = min(r_intervals) if r_intervals else None
        statisticsData["sMaxInterval"] = max(s_intervals) if s_intervals else None
        statisticsData["rMaxInterval"] = max(r_intervals) if r_intervals else None
        statisticsData["sAvgInterval"] = np.mean(s_intervals) if s_intervals else None
        statisticsData["rAvgInterval"] = np.mean(r_intervals) if r_intervals else None
        statisticsData["sVarInterval"] = np.var(s_intervals) if s_intervals else None
        statisticsData["rVarInterval"] = np.var(r_intervals) if r_intervals else None
        statisticsData["sRatio"] = len(s_lengths) / (len(r_lengths) + len(s_lengths)) if len(r_lengths) + len(s_lengths) > 0 else None

        return statisticsData, packetData
    
    def get_cnc_data(self, csv):
        metadatas = []
        statisticsDatas = []
        packetDatas = []
        for i, line in enumerate(csv):
            if i > 30:
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
            statisticsData = {
                "sPackets": None,
                "rPackets": None,
                "sTotalSize": None,
                "rTotalSize": None,
                "sMinSize": None,
                "rMinSize": None,
                "sMaxSize": None,
                "rMaxSize": None,
                "sAvgSize": None,
                "rAvgSize": None,
                "sVarSize": None,
                "rVarSize": None,
                "sMinInterval": None,
                "rMinInterval": None,
                "sMaxInterval": None,
                "rMaxInterval": None,
                "sAvgInterval": None,
                "rAvgInterval": None,
                "sVarInterval": None,
                "rVarInterval": None,
                "sRatio": None
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

            sBytes = int(line[2].strip())
            rBytes = int(line[3].strip())
            sPackets = int(line[9].strip())
            rPackets = int(line[10].strip())
            directions = line[17].strip()
            flags = line[18].strip()
            lengths = line[19].strip()
            times = line[20].strip()

            directions = list(map(int, directions[1:-1].split("|")))
            flags = list(map(int, flags[1:-1].split("|")))
            lengths = list(map(int, lengths[1:-1].split("|")))
            times = times[1:-1].split("|")

            statisticsData["sPackets"] = sPackets
            statisticsData["rPackets"] = rPackets
            statisticsData["sTotalSize"] = sBytes
            statisticsData["rTotalSize"] = rBytes
            statisticsData["sRatio"] = sPackets / (sPackets + rPackets) if sPackets + rPackets > 0 else None

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

            statisticsData["sMinSize"] = min(s_lengths) if s_lengths else None
            statisticsData["rMinSize"] = min(r_lengths) if r_lengths else None
            statisticsData["sMaxSize"] = max(s_lengths) if s_lengths else None
            statisticsData["rMaxSize"] = max(r_lengths) if r_lengths else None
            statisticsData["sAvgSize"] = np.mean(s_lengths) if s_lengths else None
            statisticsData["rAvgSize"] = np.mean(r_lengths) if r_lengths else None
            statisticsData["sVarSize"] = np.var(s_lengths) if s_lengths else None
            statisticsData["rVarSize"] = np.var(r_lengths) if r_lengths else None
            statisticsData["sMinInterval"] = min(s_intervals) if s_intervals else None
            statisticsData["rMinInterval"] = min(r_intervals) if r_intervals else None
            statisticsData["sMaxInterval"] = max(s_intervals) if s_intervals else None
            statisticsData["rMaxInterval"] = max(r_intervals) if r_intervals else None
            statisticsData["sAvgInterval"] = np.mean(s_intervals) if s_intervals else None
            statisticsData["rAvgInterval"] = np.mean(r_intervals) if r_intervals else None
            statisticsData["sVarInterval"] = np.var(s_intervals) if s_intervals else None
            statisticsData["rVarInterval"] = np.var(r_intervals) if r_intervals else None

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
            statisticsDatas.append(statisticsData)
            packetDatas.append(packetData)

        return metadatas, statisticsDatas, packetDatas
    
    def split_train_test(self):
        # Splitting the data into train and test, 60% train and 40% test
        train = {"body": [], "label": []}
        test = {"body": [], "label": []}
        labels = []

        for i, session in enumerate(self.sessions["session"]):
            # print("Processing session " + str(i) + "...")

            metadata = session.metadata
            body = session.body
            label = session.label

            if metadata["protocol"] == "TCP/IP":
                idxs = []

                if label not in labels:
                    labels.append(label)

                    for j, s in enumerate(self.sessions["session"]):
                        if s.label == label:
                            idxs.append(j)

                    train_idxs = np.random.choice(idxs, round(len(idxs)*0.5), replace=False)
                    test_idxs = [j for j in idxs if j not in train_idxs]

                    for idx in train_idxs:
                        train["body"].extend(self.sessions["session"][idx].body)
                        train["label"].extend([label] * len(self.sessions["session"][idx].body))
                    for idx in test_idxs:
                        test["body"].extend(self.sessions["session"][idx].body)
                        test["label"].extend([label] * len(self.sessions["session"][idx].body))
                else:
                    continue
            else:
                idxs = [i for i in range(len(body))]
                train_idxs = np.random.choice(idxs, round(len(idxs)*0.6), replace=False)
                test_idxs = [i for i in idxs if i not in train_idxs]

                for idx in train_idxs:
                    train["body"].append(body[idx])
                    train["label"].append(label)
                for idx in test_idxs:
                    test["body"].append(body[idx])
                    test["label"].append(label)

        self.sessions["train"] = train
        self.sessions["test"] = test

    def get_train_test_data(self):
        x_train = []
        y_train = []
        x_test = []
        y_test = []

        try:
            for i, body in enumerate(self.sessions["train"]["body"]):
                x_train.append(body)
                y_train.append(self.sessions["train"]["label"][i])
        except:
            print(len(self.sessions["train"]["body"]))
            print(len(self.sessions["train"]["label"]))
            raise(Exception("Error in train data"))

        for i, body in enumerate(self.sessions["test"]["body"]):
            x_test.append(body)
            y_test.append(self.sessions["test"]["label"][i])

        return x_train, y_train, x_test, y_test