import logging

logger = logging.getLogger("logger")

def normalize(value, value_type):
    if value == 0:
        return 0.0
    
    if value_type == "protocol":
        if "ZBEE_NWK" in value:
            return 1.0
    
    if value_type == "delta_time":
        if value >= 1000:
            return 1.0
        else:
            return value / 1000
    
    if value_type == "length":
        if value >= 128:
            return 1.0
        else:
            return value / 128
        
    if value_type == "direction":
        return float(value)
    
    logger.error(f"Cannot normalize {value_type} {value}")
    exit(1)

def extract_features(flows, labels, mode):
    X = []
    y = []
    
    y_dict = {"name": 3, "dtype": 4, "vendor": 5}
    label_index = {labels[y_dict[mode]]:i for i, labels in enumerate(labels)}

    for key in flows.value:
        flow = flows.value[key]

        if (key.sid, key.did) in [('0x0000', '0xffff'), ('0x0001', '0xffff'), ('0x3990', '0xffff')]:
            continue

        for i in range(0, len(flow), 4):
            X_tmp = []
            y_tmp = None

            for label in labels:
                if label[0] in [key.sid, key.did] and (label[1], label[2]) == (key.protocol, key.additional):
                    y_tmp = label[y_dict[mode]]
                    break
            else:
                # logger.error(f"Cannot find label for {key.sid}, {key.did}, {key.protocol}, {key.additional} - 1")
                break

            for j in range(4):
                try:
                    X_tmp.append([
                        normalize(flow[i + j].delta_time, "delta_time"),
                        normalize(flow[i + j].direction, "direction"),
                        normalize(flow[i + j].length, "length"),
                        normalize(flow[i + j].protocol, "protocol")
                    ])
                except:
                    X_tmp.append([0.0] * 4)

            X.append(X_tmp)
            y.append(y_tmp)
    
    if len(X) != len(y):
        logger.error(f"X and y have different length (X:{len(X)} != y:{len(y)})")
        exit(1)

    y = [int(label_index[label]) for label in y]

    return X, y

def extract_features_b(flows, labels, mode):
    X = []
    y = []
    
    y_dict = {"name": 3, "dtype": 4, "vendor": 5}
    label_index = {labels[y_dict[mode]]:i for i, labels in enumerate(labels)}

    for key in flows.value:
        flow = flows.value[key]

        if (key.sid, key.did) in [('0x0000', '0xffff'), ('0x0001', '0xffff'), ('0x3990', '0xffff')]:
            continue

        for i in range(0, len(flow), 4):
            X_tmp = []
            y_tmp = None

            for label in labels:
                if label[0] in [key.sid, key.did] and (label[1], label[2]) == (key.protocol, key.additional):
                    y_tmp = label[y_dict[mode]]
                    break
            else:
                # logger.error(f"Cannot find label for {key.sid}, {key.did}, {key.protocol}, {key.additional} - 1")
                break

            for j in range(4):
                try:
                    X_tmp.extend([
                        normalize(flow[i + j].delta_time, "delta_time"),
                        normalize(flow[i + j].direction, "direction"),
                        normalize(flow[i + j].length, "length"),
                        normalize(flow[i + j].protocol, "protocol")
                    ])
                except:
                    X_tmp.extend([0.0] * 4)

            X.append(X_tmp)
            y.append(y_tmp)
    
    if len(X) != len(y):
        logger.error(f"X and y have different length (X:{len(X)} != y:{len(y)})")
        exit(1)

    y = [int(label_index[label]) for label in y]

    return X, y