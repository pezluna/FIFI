'''
Not Started
1. get_tuple_zigbee, get_tuple_15d4 함수 구현
2. get_tuple 함수 구조 검토
3. 모델 학습 방법 수립
    a. 학습 데이터와 테스트 데이터, 검증 데이터를 나누는 방법
    b. 학습에 사용할 모델 선택(DT, RF, SVM, RNN, LSTM, etc.)
    c. 학습 모델 구조 설계(epoch, batch size, hidden layer, etc.)
4. 검토 및 검증
    a. 모델 학습 및 평가

In Progress
1. 주요 특징 선정 방법 수립
    a. 헤더의 각 상관계수 도출
    b. 도출된 상관계수를 통해 유사한 특징들 중 대표 특징 선정

Done
1. 데이터 수집 및 증강
    a. 데이터 수집(Samsung SmartThings Hub, Aqara Smart Hub)
    b. 데이터 증강(aug_pcap 함수 구현)
2. flow 생성
    a. classify_packets 함수 구현
    b. extract_features 함수 구현
'''

import pyshark
from scapy import *

import os
import time

def load_files(path):
    global start_time
    print(f"[{time.time - start_time}] Loading files from {path}...")
    pcaps = []

    for file in os.listdir(path):
        if file.endswith(".pcapng"):
            pcap = pyshark.FileCapture(path + file, include_raw=True, use_json=True)

            pcaps.append(pcap)
    
    print(f"[{time.time - start_time}] Loaded {len(pcaps)} files from {path}.")
    
    return pcaps


def get_channel(small_tuple):
    '''
    원활한 진행을 위해, 실제 수집 채널을 하드코딩하여 반환하였음
    실제 환경에서는 해당 함수를 수정하여 사용할 것
    '''
    if '0x9a65' in small_tuple or '0x1aa9':
        return 19
    else:
        return 15



def get_tuple_zigbee(pkt):
    '''
    1. Zigbee 구조로부터 다음의 정보 획득
        * Source Node
        * Destination Node
        * Time
        * Channel
        * Protocol
    2. 획득한 정보를 튜플로 변환 및 반환
    '''
    pass

def get_tuple_15d4(pkt):
    '''
    1. IEEE 802.15.4 구조로부터 다음의 정보 획득
        * Source Node
        * Destination Node
        * Time
        * Channel
        * Protocol
    2. 획득한 정보를 튜플로 변환 및 반환
    '''
    pass

def get_tuple(pkt):
    '''
    튜플의 구조
    (Time, Protocol, Source Node, Destination Node, Channel)
    '''
    protocol = {
        "Zigbee": get_tuple_zigbee,
        "IEEE 802.15.4": get_tuple_15d4,
    }

    return protocol[pkt.highest_layer](pkt)

def get_flow(pcap):
    global start_time
    print(f"[{time.time - start_time}] Classifying packets...")
    flow = {}

    for pkt in pcap:
        try:
            t = get_tuple(pkt)
        except:
            continue
        
        # flow 객체 생성
        if t in flow:
            # 정방향 패킷인 경우
            flow[t].append(pkt)
        else:
            if (t[0], t[1], t[3], t[2], t[5]) in flow:
                # 역방향 패킷인 경우
                flow[(t[0], t[1], t[3], t[2], t[5])].append(pkt)
            else:
                # 새로운 flow인 경우
                flow[t] = [pkt]

    print(f"[{time.time - start_time}] Classified {len(flow)} flows.")
    return flow

def extract_features(flow):
    '''
    특징의 종류
    * 시간 간격 (첫 패킷은 0으로 설정)
    * 패킷 길이
    * 전송 프로토콜
    * 전송 방향(정방향은 0, 역방향은 1)
    '''
    global start_time
    print(f"[{time.time - start_time}] Extracting features...")

    features = []

    for f in flow:
        # 시간 간격
        prev_timestamp = float(flow[f][0].sniff_timestamp)
        intervals = []
        for pkt in flow[f]:
            intervals.append(float(pkt.sniff_timestamp) - prev_timestamp)
            prev_timestamp = float(pkt.sniff_timestamp)

        # 패킷 길이
        lengths = []
        for pkt in flow[f]:
            lengths.append(len(pkt.get_raw_packet()))

        # 전송 프로토콜
        protocols = []
        for pkt in flow[f]:
            protocols.append(pkt.highest_layer)

        # 전송 방향
        directions = []
        for pkt in flow[f]:
            if f[2] == pkt.source:
                directions.append(0)
            else:
                directions.append(1)
        
        # 특징을 하나의 리스트로 묶어서 반환
        features.append([intervals, lengths, protocols, directions])
    
    print(f"[{time.time - start_time}] Extracted {len(features)} features.")
    return features

def calc_feature_importance(features):
    '''
    각 특징들로부터 특징 중요도를 계산하여 반환
    '''
    pass

if __name__ == "__main__":
    global start_time
    start_time = time.time()

    # 특징이 저장된 폴더(../feature) 내부에 아무 파일이 존재하지 않을 경우
    if len(os.listdir("../feature")) == 0:
        # Zigbee 폴더 내부의 각 폴더로부터 pcap 파일 로드
        pcaps = []
        for folder in os.listdir("../Zigbee/"):
            pcaps.append(load_files("../Zigbee/" + folder + "/"))

        # flow 생성
        flows = []

        for pcap in pcaps:
            flows.append(get_flow(pcap))
        
        # 각 flow로부터 특징 추출
        features = []
        for flow in flows:
            features.append(extract_features(flow))

    # 모델 학습
    print(f"[{time.time - start_time}] Training model...")

    # Todo: 모델 학습 방법 수립

    print(f"[{time.time - start_time}] Finished.")