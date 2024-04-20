import pyshark

def zigbee_reader(f):
    pcap = pyshark.FileCapture(f, include_raw=True, use_json=True)
    
    data = {}
    for i in range(8):
        try:
            pkt = pcap[i]

            # metadata
            data["srcId"] = None # Need to implement
            data["dstId"] = None # Need to implement
            data["protocol"] = None # Need to implement
            data["remarks"] = None # Need to implement

            # packet data
            data["rawTime"] = float(pkt.sniff_timestamp)
            data["rawLength"] = pkt.length
            data["payload"] = None # Need to implement
            data["capturedLength"] = None # Need to implement
        except:
            data["rawLength"] = 0
            data["capturedLength"] = 0
            data["payload"] = "\x00"
    
    return data

def cnc_reader(f):
    pass