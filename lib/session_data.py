# Session
# {
#     "data": [
#         {
#             "protocol": str,
#             "length": int,
#             "delta_time": float,
#             "direction": int
#         },
#         ...
#     ], 
#     "label": tuple
# }

# Raw_Session
# {
#     "data": [
#         {
#             "protocol": str,
#             "length": int,
#             "direction": int,
#             "raw_time": float
#         },
#         ...
#     ], 
#     "label": tuple
# }

import os
import pyshark
import pickle
import json

import logging
from lib.log_conf import init_logger

logger = logging.getLogger("logger")

class Sessions:
    def __init__(self):
        self.path = "./data/sessions.pkl"
        self.raw_sessions = {}
        self.sessions = {}

        # Check existence of network session files
        if not os.path.exists(self.path):
            logger.debug("Session file not found. Generating session file...")
            self.raw_sessions = self.generate_raw_sessions()

            for session_id in self.raw_sessions:
                self.sessions[session_id] = self.generate_session(self.raw_sessions[session_id])
            
            with open(self.path, 'wb') as f:
                pickle.dump(self.sessions, f)
        
        else:
            logger.debug("Session file found. Loading session file...")
            self.sessions = self.load_sessions(self.path)

    def generate_raw_sessions(self):
        raw_sessions = {}
        
        # Load network session files
        zigbee_path = "./dataset/zigbee/"
        zwave_path = "./dataset/zwave/"
        zigbee_files = self.load_zigbee_files(zigbee_path)
        zwave_files = self.load_zwave_files(zwave_path)

        # IMPLEMENTATION NEEDED
        # Load Zigbee network session files
        for file in zigbee_files:
            # IMPLEMENTATION NEEDED
            pass

        for file in zwave_files:
            f = json.load(open(file))
            stat = f["stat"]

            for home_id in list(stat.keys()):
                for tmp in stat[home_id]:
                    for src_to_dst in stat[home_id][tmp]:
                        if "-" not in src_to_dst:
                            continue
                        src, dst = src_to_dst.split("-")

                        # Get direction of the packet
                        direction = None
                        forward_session_id = self.get_session_id(src, dst, "Z-Wave", home_id)
                        backward_session_id = self.get_session_id(dst, src, "Z-Wave", home_id)

                        if backward_session_id in raw_sessions:
                            direction = -1
                        else:
                            direction = 1
                        
                        # Get label
                        label = self.get_zwave_label(src, dst, home_id)

                        if forward_session_id not in raw_sessions and direction == 1:
                            # Create new session
                            raw_sessions[forward_session_id] = {
                                "data": [],
                                "label": label
                            }
                        
                        payloads = stat[home_id]["nonces_s2"][src_to_dst]
                        for payload in payloads:
                            raw_time = payload[0]
                            length = len(payload[2])

                            # Add packet to the session
                            if direction == 1:
                                raw_sessions[forward_session_id]["data"].append({
                                    "protocol": "Z-Wave",
                                    "length": length,
                                    "direction": direction,
                                    "raw_time": raw_time
                                })
                                raw_sessions[forward_session_id]["label"] = label
                            else:
                                raw_sessions[backward_session_id]["data"].append({
                                    "protocol": "Z-Wave",
                                    "length": length,
                                    "direction": direction,
                                    "raw_time": raw_time
                                })
                                raw_sessions[backward_session_id]["label"] = label
        
        return raw_sessions
    
    def load_zigbee_files(self, path):
        files = []
        for file in os.listdir(path):
            if file.endswith(".pcap"):
                files.append(path + file)
        return files
    
    def load_zwave_files(self, path):
        files = []
        for file in os.listdir(path):
            if file.endswith(".json"):
                files.append(path + file)
        return files

    def load_sessions(self, path):
        with open(path, 'rb') as f:
            return pickle.load(f)
    
    def get_session_id(self, src, dst, protocol, additional):
        session_id = tuple([src, dst, protocol, additional]) # IMPLEMENTATION NEEDED
        return session_id
    
    def generate_session(self, raw_session):
        session = {}
        session["data"] = raw_session["data"]
        session["label"] = raw_session["label"]
        try:
            session["data"][0]["delta_time"] = 0
        except:
            logger.error(f"Invalid raw_session: {raw_session}")
            raise ValueError(f"Invalid session: {session}")
        for i in range(1, len(session["data"])):
            session["data"][i]["delta_time"] = session["data"][i]["raw_time"] - session["data"][i-1]["raw_time"]

        return session
    
    def get_zwave_label(self, src, dst, home_id):
        zwave_label_path = "./data/zwave_label.csv"

        labels = open(zwave_label_path).readlines()
        for label in labels:
            address, device_name, node_type, homeid, _ = label.split(',')
            vendor_name = device_name.split(' ')[0]
            address = address.strip()
            homeid = homeid.strip()
            device_name = device_name.strip()
            node_type = node_type.strip()

            if not homeid.lower() == home_id.lower():
                continue

            if node_type == "Coordinator":
                continue
            
            if address == src:
                return (device_name, vendor_name, node_type)
            elif address == dst:
                return (device_name, vendor_name, node_type)
        
        logger.error(f"Invalid address: {address}")
        logger.error(f"src: {src}, dst: {dst}")
        logger.error(f"home_id: {home_id.lower()}, homeid: {homeid.lower()}")
        raise ValueError(f"Invalid address: {address}")
    
    def reset(self):
        os.remove(self.path)
        self.__init__()

