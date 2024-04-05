# feature structure
# {
#     'protocol': protocol,
#     'length': length of payload,
#     'delta_time': time difference between this packet and the previous packet,
#     'direction': direction of the packet (1: src -> dst, -1: dst -> src, 0: padding)
# }

import pyshark
import numpy as np
# from lib.visualization import visualize_image

import logging
from lib.log_conf import init_logger

logger = logging.getLogger("logger")

def get_label(session, session_id):
    # IMPLEMENTATION NEEDED
    return 0

def session_to_sequences(session):
    length_of_sequence = 7
    sequences = []

    # IMPLEMENTATION NEEDED

    for i in range(0, len(session), length_of_sequence):
        if i + length_of_sequence > len(session):
            sequence = session[i:]
            # Pad sequence
            sequence.extend([{
                'protocol': session[0]['protocol'],
                'length': sum([data['length'] for data in sequence]) / len(sequence),
                'delta_time': sum([data['delta_time'] for data in sequence]) / len(sequence),
                'direction': 0
            }] * (i + length_of_sequence - len(session)))
        else:
            sequence = session[i:i+length_of_sequence]
            sequences.append(sequence)

    return sequences

def normalize_sequences(sequences):
    max_length = 60
    max_delta_time = 0.1

    for sequence in sequences:
        for data in sequence:
            try:
                data['length'] = 255 if data['length'] > max_length else data['length'] * 255 / max_length
            except:
                logger.error(f"Invalid data: {data} from {sequences}")
                raise ValueError(f"Invalid data: {data}")
            data['delta_time'] = 255 if data['delta_time'] > max_delta_time else data['delta_time'] * 255 / max_delta_time

            if data['direction'] == 1:
                data['direction'] = 255
            elif data['direction'] == -1:
                data['direction'] = 0
            else:
                data['direction'] = 128
            
            if data['protocol'] == 'Zigbee':
                data['protocol'] = 0
            elif data['protocol'] == 'Z-Wave':
                data['protocol'] = 255
            else:
                logger.error("Invalid protocol: %s", data['protocol'])
                raise ValueError(f"Invalid protocol: {data['protocol']}")

    return sequences

def sequences_to_image_arrays(sequences):
    # size of image: 7x4
    arrs = []
    for seqcuence in sequences:
        row = []
        for data in seqcuence:
            row.append([data['protocol'], data['length'], data['delta_time'], data['direction']])
        arrs.append(row)
    
    # data to array
    arrs = np.array(arrs)
    return arrs

def preprocess_for_cnn(sessions):
    arrs = []
    labels = []
    cnts = []

    for session_id in sessions.sessions:
        session_data = sessions.sessions[session_id]["data"]
        session_label = sessions.sessions[session_id]["label"]
        sequences = session_to_sequences(session_data)
        sequences = normalize_sequences(sequences)
        imgs = sequences_to_image_arrays(sequences)
        cnt = len(imgs)

        arrs.append(imgs)
        labels.append(session_label)
        cnts.append(cnt)

    return arrs, labels, cnts

def split_data(arrs, labels, cnts):
    X_train = []
    X_test = []
    y_train = []
    y_test = []

    # IMPLEMENTATION NEEDED
    for i in range(len(arrs)):
        arr = arrs[i]
        label = labels[i]
        cnt = cnts[i]

        X_train.append(arr[:int(cnt * 0.8)])
        X_test.append(arr[int(cnt * 0.8):])
        y_train.append([label] * int(cnt * 0.8))
        y_test.append([label] * (cnt - int(cnt * 0.8)))

    print(f"X_train: {len(X_train)}, X_test: {len(X_test)}, y_train: {len(y_train)}, y_test: {len(y_test)}")
    X_train = np.array(X_train)
    X_test = np.array(X_test)
    y_train = np.array(y_train)
    y_test = np.array(y_test)

    return X_train, X_test, y_train, y_test