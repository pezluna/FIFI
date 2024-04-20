import sys
import os
import json
import numpy as np
import pyshark
from datetime import datetime

class Sessions:
    def __init__(self):
        self.sessions_path = "./sessions/"
        self.zigbee_raw_path = "./raw/zigbee/"
        self.cnc_raw_path = "./raw/cnc/"
        self.sessions = {
            "metadata": [],
            "body": [],
            "train": [],
            "test": [],
            "label": []
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
        # Zigbee
        for file in os.listdir(self.zigbee_raw_path):
            if file.endswith(".pcapng") or file.endswith(".pcap"):
                print("Processing " + file + "...")
                with pyshark.FileCapture(os.path.join(self.zigbee_raw_path, file), include_raw=True, use_json=True) as pcap:
                    metadata = self.get_zigbee_metadata(pcap)
                    if metadata is None:
                        continue
                    bodydata = self.get_zigbee_bodydata(pcap)
                    if bodydata is None:
                        raise Exception("Invalid body data.")

                    reverse_metadata = {
                        "srcId": metadata["dstId"],
                        "dstId": metadata["srcId"],
                        "protocol": metadata["protocol"],
                        "remarks": metadata["remarks"]
                    }

                    if metadata not in self.sessions["metadata"] and reverse_metadata not in self.sessions["metadata"]:
                        self.sessions["metadata"].append(metadata)
                        self.sessions["body"].append([bodydata])
                    elif metadata in self.sessions["metadata"]:
                        index = self.sessions["metadata"].index(metadata)
                        self.sessions["body"][index].append(bodydata)
                    elif reverse_metadata in self.sessions["metadata"]:
                        index = self.sessions["metadata"].index(reverse_metadata)
                        self.sessions["body"][index].append(bodydata)
                    else:
                        raise Exception("Invalid metadata.")
        
        # CNC
        for file in os.listdir(self.cnc_raw_path):
            if file.endswith(".csv"):
                print("Processing " + file + "...")

                with open(os.path.join(self.cnc_raw_path, file)) as f:
                    metadatas, statisticsDatas, packetDatas = self.get_cnc_data(f)
                    for i, metadata in enumerate(metadatas):
                        try:
                            reverse_metadata = {
                                "srcId": metadata["dstId"],
                                "dstId": metadata["srcId"],
                                "protocol": metadata["protocol"],
                                "remarks": metadata["remarks"]
                            }
                        except:
                            print("Error in file " + file + " at line " + str(i) + ".")
                            print("Metadata: " + str(metadata))
                            for key in metadata:
                                print(key + ": " + str(metadata[key]))
                            raise Exception("Invalid metadata.")

                        if metadata not in self.sessions["metadata"] and reverse_metadata not in self.sessions["metadata"]:
                            self.sessions["metadata"].append(metadata)
                            self.sessions["body"].append([(statisticsDatas[i], packetDatas[i])])
                            if "benign" in file:
                                self.sessions["label"].append("benign")
                            elif "mirai" in file:
                                self.sessions["label"].append("mirai")
                            elif "qbot" in file:
                                self.sessions["label"].append("qbot")
                            elif "kaiten" in file:
                                self.sessions["label"].append("kaiten")
                            else:
                                raise Exception("Invalid file name")
                        elif metadata in self.sessions["metadata"]:
                            index = self.sessions["metadata"].index(metadata)
                            self.sessions["body"][index].append((statisticsDatas[i], packetDatas[i]))
                        elif reverse_metadata in self.sessions["metadata"]:
                            index = self.sessions["metadata"].index(reverse_metadata)
                            self.sessions["body"][index].append((statisticsDatas[i], packetDatas[i]))
                        else:
                            raise Exception("Invalid metadata.")
    
        print("Length of Metadata: ", len(self.sessions["metadata"]))
        print("Length of Labels: ", len(self.sessions["label"]))
        for i, metadata in enumerate(self.sessions["metadata"]):
            print(" >> Metadata " + str(i) + ": " + str(metadata))
            print(" >> Length of Body " + str(i) + ": " + str(len(self.sessions["body"][i])))
                    
    def save(self):
        with open(os.path.join(self.sessions_path, "sessions.json"), "w") as f:
            json.dump(self.sessions, f)

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

        for i, pkt in enumerate(pcap):
            if 'ZBEE_NWK' in pkt.highest_layer:
                if pkt.wpan.dst16 == "0xffff":
                    continue
                if srcId is None:
                    srcId = pkt.wpan.src16
                currentTime = float(pkt.sniff_timestamp)
                direction = 0 if srcId == pkt.wpan.src16 else 1

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
                        packetData["deltaTime"].append(interval)
                    else:
                        pass
                    last_sTime = currentTime
                else:
                    r_lengths.append(pkt.length)
                    if last_rTime is not None:
                        interval = currentTime - last_rTime
                        r_intervals.append(interval)
                        packetData["deltaTime"].append(interval)
                    else:
                        pass
                    last_rTime = currentTime

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
            if i > 300:
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

            metadatas.append(metadata)
            statisticsDatas.append(statisticsData)
            packetDatas.append(packetData)

        return metadatas, statisticsDatas, packetDatas
    
    def split_train_test(self):
        # Splitting the data into train and test, 60% train and 40% test per each label
        train = {"body": [], "label": []}
        test = {"body": [], "label": []}
        label = []
        for i, metadata in enumerate(self.sessions["metadata"]):
            cur_label = self.sessions["label"][i]

            if cur_label not in label:
                print("Processing label " + cur_label + "...")
                label.append(cur_label)
                label_count = self.sessions["label"].count(cur_label)
                
                if label_count == 1:
                    tmp = [t for t in range(len(self.sessions["body"][i]))]
                    print("label: " + cur_label + ", count: " + str(len(tmp)) + ", tmp: " + str(tmp))
                    print(self.sessions["body"][i])
                    train_idxs = np.random.choice(tmp, round(len(self.sessions["body"][i])*0.6), replace=False)
                    test_idxs = [t for t in tmp if t not in train_idxs]

                    for idx in train_idxs:
                        train["body"].append(self.sessions["body"][idx])
                        train["label"].append(cur_label)
                    for idx in test_idxs:
                        test["body"].append(self.sessions["body"][idx])
                        test["label"].append(cur_label)
                else:
                    train_count = int(label_count * 0.6)
                    test_count = label_count - train_count

                    label_idxs = [j for j, x in enumerate(self.sessions["label"]) if x == cur_label]

                    train_idxs = np.random.choice(label_idxs, train_count, replace=False)
                    test_idxs = [j for j in label_idxs if j not in train_idxs]

                    for idx in train_idxs:
                        train["body"].append(self.sessions["body"][idx])
                        train["label"].append(cur_label)
                    for idx in test_idxs:
                        test["body"].append(self.sessions["body"][idx])
                        test["label"].append(cur_label)
            else:
                continue

        self.sessions["train"] = train
        self.sessions["test"] = test

    def get_train_test_data(self):
        x_train = []
        y_train = []
        x_test = []
        y_test = []

        for i in range(len(self.sessions["metadata"])):
            x_train.append(self.sessions["train"][i])
            y_train.append(self.sessions["label"][i])
            x_test.append(self.sessions["test"][i])
            y_test.append(self.sessions["label"][i])

        return x_train, y_train, x_test, y_test
    
    def map_labels(self, label):
        for i, metadata in enumerate(self.sessions["metadata"]):
            if metadata["protocol"] == "Zigbee":
                for j, id in enumerate(label["id"]):
                    if metadata["srcId"] == id or metadata["dstId"] == id:
                        if label["remarks"][j] == metadata["remarks"] and label["protocol"][j] == metadata["protocol"]:
                            self.sessions["label"].append(label["label"][j])
                            break