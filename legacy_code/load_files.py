import os
import pyshark
import pickle
import logging
import flow

logger = logging.getLogger("logger")

def save_flows(flows, path):
    with open(path, 'wb') as f:
        pickle.dump(flows, f)

def load_flows(path):
    with open(path, 'rb') as f:
        return pickle.load(f)

def load_files(path):
    pcaps = []
    for file in os.listdir(path):
        if file.endswith(".pcapng"):
            pcap = pyshark.FileCapture(path + file, include_raw=True, use_json=True)

            pcaps.append(pcap)
    return pcaps

def load_model(path):
    with open(path, 'rb') as f:
        return pickle.load(f)

def load_lables(path):
    labels = []

    with open(path, 'r') as f:
        # 파일은 csv 형태로 저장되어 있음
        # 첫 줄은 헤더이므로 제외
        f.readline()
        
        while True:
            line = f.readline()
            if not line:
                break

            # 각 줄의 첫 번째 문자가 '#'이면 주석이므로 제외
            if line[0] == '#':
                continue
            
            # 각 줄은 다음과 같은 형태로 저장되어 있음
            # id, protocol, additional, 'name', 'type', 'vendor'
            # 0, 1, 2, 3, 4, 5
            line = line.replace('\n', '')
            line = line.split(',')
            labels.append((line[0], line[1], line[2], line[3], line[4], line[5]))

    return labels

if __name__ == '__main__':
    print('This is not a runnable file.')
    exit(1)