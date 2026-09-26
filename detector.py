traffic = {}

def detect(packet):

    src = packet[0][1].src

    if src not in traffic:
        traffic[src] = 0

    traffic[src] += 1

    if traffic[src] > 50:
        return "Traffic Spike Detected"

    return None