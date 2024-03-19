import pyshark
from scapy.all import *
import random
import datetime

conf.dot15d4_protocol = 'zigbee'

def get_timestamp_from_date(date):
    # 주어진 날짜(KST)를 timestamp로 변환
    ret = datetime.datetime(date.year, date.month, date.day, date.hour, date.minute, date.second, tzinfo=datetime.timezone(datetime.timedelta(hours=9)))

    return ret.timestamp()

def get_multiplied_intervals(intervals):
    return [i * random.uniform(0.97, 1.03) for i in intervals]

def get_intervals(packets):
    intervals = []
    prev_timestamp = float(cap[0].sniff_timestamp)
    for c in cap:
        intervals.append(float(c.sniff_timestamp) - prev_timestamp)
        prev_timestamp = float(c.sniff_timestamp)
    
    intervals = intervals[1:]

    return intervals

def aug_pcap(out_filename_prefix, intervals, capture_date, epoch_num=10):
    global cap

    print('Date: ' + str(capture_date))
    
    # 총 epoch_num(default: 10)번의 epoch를 돌면서, 각 epoch마다 패킷 간의 시간 간격을 랜덤하게 조정하여 새로운 pcap 파일을 생성
    for epoch in range(epoch_num):
        multiplied_intervals = get_multiplied_intervals(intervals)

        # 새로운 타임스탬프 정보 생성
        prev_timestamp = get_timestamp_from_date(capture_date)
        packets = []
        i = 0

        # 새로운 패킷을 생성하여 packets에 추가
        for c in cap:
            pkt = Dot15d4(c.get_raw_packet())
            try:
                pkt.time = prev_timestamp
                packets.append(pkt)
                prev_timestamp += multiplied_intervals[i]
            except:
                pass
            finally:
                i += 1

        # 패킷 구간의 길이가 10800초 쯤이 되도록 임의의 구간 중 1개를 선택
        while True:
            start = random.randint(0, len(packets) - 1)
            if packets[-1].time - packets[start].time > 10800:
                # 선택된 구간을 10800초 쯤이 되도록 잘라냄
                for i in range(start, len(packets)):
                    if packets[i].time - packets[start].time > 10800:
                        packets = packets[start:i+1]
                        
                        # 새로운 pcap 파일 생성
                        wrpcap('../Zigbee/' + out_filename_prefix + str(epoch) + '.pcapng', packets)

                        return

if __name__ == '__main__':
    captured_dates = [
        (2023, 5, 1, 11, 3, 2),
        (2023, 5, 2, 11, 5, 8),
        (2023, 5, 3, 11, 12, 6),
        (2023, 5, 4, 11, 1, 48),
        (2023, 5, 8, 11, 3, 0),
        (2023, 5, 9, 11, 0, 8),
        (2023, 5, 10, 11, 0, 15),
        (2023, 5, 11, 11, 3, 15),
        (2023, 5, 12, 11, 2, 50),
        (2023, 5, 15, 11, 3, 2),
        (2023, 5, 16, 11, 5, 8),
        (2023, 5, 17, 11, 12, 6),
        (2023, 5, 18, 11, 1, 48),
        (2023, 5, 19, 11, 3, 0),
        (2023, 5, 22, 11, 0, 8),
        (2023, 5, 23, 11, 0, 15),
        (2023, 5, 24, 11, 3, 15),
        (2023, 5, 25, 11, 2, 50),
        (2023, 5, 26, 11, 3, 2),
        (2023, 5, 29, 11, 5, 8),
        (2023, 5, 30, 11, 12, 6),
        (2023, 5, 31, 11, 1, 48),
        (2023, 6, 1, 10, 59, 53),
        (2023, 6, 2, 11, 0, 8),
        (2023, 6, 5, 11, 2, 16),
        (2023, 6, 7, 11, 1, 1),
        (2023, 6, 8, 11, 2, 31),
        (2023, 6, 9, 11, 0, 2),
        (2023, 6, 12, 11, 1, 42),
        (2023, 6, 13, 11, 0, 9),
        (2023, 6, 14, 11, 0, 21),
        (2023, 6, 15, 11, 1, 1),
        (2023, 6, 16, 11, 0, 2),
        (2023, 6, 19, 10, 59, 48),
        (2023, 6, 20, 10, 59, 51),
        (2023, 6, 21, 11, 0, 1),
        (2023, 6, 26, 11, 4, 2),
        (2023, 6, 27, 11, 0, 8),
        (2023, 6, 28, 11, 2, 39),
        (2023, 6, 29, 11, 9, 1),
        (2023, 6, 30, 11, 1, 10),
        (2023, 7, 3, 11, 0, 2),
        (2023, 7, 4, 11, 0, 16),
        (2023, 7, 5, 11, 0, 32),
        (2023, 7, 10, 11, 1, 1),
        (2023, 7, 11, 11, 0, 9),
        (2023, 7, 13, 11, 0, 29),
        (2023, 7, 14, 11, 1, 31),
        (2023, 7, 17, 10, 59, 48),
        (2023, 7, 18, 10, 59, 17),
        (2023, 7, 19, 11, 0, 51),
        (2023, 7, 20, 11, 0, 27),
        (2023, 7, 21, 11, 13, 28),
        (2023, 7, 24, 11, 1, 8),
        (2023, 7, 25, 11, 9, 42),
        (2023, 7, 26, 11, 19, 33),
        (2023, 7, 27, 11, 1, 2),
        (2023, 7, 28, 11, 2, 0),
        (2023, 7, 31, 11, 0, 8),
        (2023, 8, 1, 10, 59, 53),
        (2023, 8, 2, 10, 59, 58),
        (2023, 8, 3, 11, 1, 16),
        (2023, 8, 4, 11, 9, 42),
        (2023, 8, 7, 11, 8, 1),
        (2023, 8, 8, 11, 0, 19),
        (2023, 8, 9, 11, 4, 2),
        (2023, 8, 10, 11, 3, 8),
        (2023, 8, 11, 10, 30, 32),
        (2023, 8, 14, 11, 4, 14),
        (2023, 8, 16, 11, 2, 1),
        (2023, 8, 17, 11, 6, 0),
        (2023, 8, 18, 10, 58, 58),
        (2023, 8, 21, 11, 0, 41),
        (2023, 8, 22, 11, 1, 12),
        (2023, 8, 28, 11, 5, 37),
        (2023, 8, 29, 11, 14, 2),
        (2023, 8, 30, 10, 36, 59),
        (2023, 8, 31, 10, 34, 8),
        (2023, 9, 1, 11, 30, 22)
    ]
    
    global cap
    cap = pyshark.FileCapture('../Zigbee/original_1.pcapng', use_json=True, include_raw=True)

    intervals = get_intervals(cap)

    print('Interval Calculation Done')

    for i in range(len(captured_dates)):
        captured_dates[i] = datetime.datetime(*captured_dates[i])

    print('Date Parsing Done')

    for i in range(len(captured_dates)):
        aug_pcap('Aqara/' + str(i) + '_', intervals, captured_dates[i], 2)