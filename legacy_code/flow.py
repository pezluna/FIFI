import os

class FlowKey:
    def __init__(self):
        self.sid = None
        self.did = None
        self.protocol = None
        self.additional = None
    
    def __str__(self):
        return str(self.sid) + '_' + str(self.did) + '_' + str(self.protocol) + '_' + str(self.additional)

    def set_key(self, pkt):
        if 'ZBEE_NWK' in pkt.highest_layer:
            # 수정 필요
            self.sid = pkt.wpan.src16
            self.did = pkt.wpan.dst16
            self.protocol = 'ZBEE_NWK'
            self.additional = pkt.wpan.dst_pan
            return True
        
        else:
            return False

class FlowValue:
    def __init__(self):
        self.raw_time = None
        self.direction = None
        self.length = None
        self.delta_time = None
        self.protocol = None
    
    def __str__(self):
        return str(self.raw_time) + '_' + str(self.direction) + '_' + str(self.length) + '_' + str(self.delta_time) + '_' + str(self.protocol)
    
    def __repr__(self):
        return str(self.raw_time) + '_' + str(self.direction) + '_' + str(self.length) + '_' + str(self.delta_time) + '_' + str(self.protocol)

    def set_raw_value(self, pkt, flow_key):
        # 수정 필요
        self.protocol = flow_key.protocol
        
        if flow_key.protocol == 'ZBEE_NWK':
            self.raw_time = float(pkt.sniff_timestamp)
            self.length = pkt.length

class Flows:
    def __init__(self):
        self.value = {}
    
    def __str__(self):
        return str(self.value)
    
    def find(self, key):
        try:
            for k in self.value:
                if k.protocol == key.protocol and k.additional == key.additional:
                    if k.sid == key.sid and k.did == key.did:
                        return k, True
                    elif k.sid == key.did and k.did == key.sid:
                        return k, False
        except:
            return None
                
        return None
    
    def create(self, key, value, direction):
        value.direction = direction
        self.value[key] = [value]
    
    def append(self, key, value, direction):
        value.direction = direction
        self.value[key].append(value)
    
    def sort(self):
        for k in self.value:
            self.value[k].sort(key=lambda x: x.raw_time)

    def tune(self):
        for k in self.value:
            self.value[k][0].delta_time = 0

            for i in range(1, len(self.value[k])):
                self.value[k][i].delta_time = self.value[k][i].raw_time - self.value[k][i-1].raw_time
    
    def print(self, path):
        for k in self.value:
            with open(path + str(k) + ".txt", 'w') as f:
                for i in range(len(self.value[k])):
                    f.write(str(self.value[k][i].delta_time) + ' ' + str(self.value[k][i].direction) + ' ' + str(self.value[k][i].length) + '\n')