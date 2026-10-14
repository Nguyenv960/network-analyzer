def check_packet_burst(summary, threshold):
    # returns whether window's packet count meets threshold
    return summary["packet_count"] >= threshold

def check_syn_volume(count, threshold):
    # returns whether SYN-without-ACK packet count meets threshold
    return count >= threshold

def check_distinct_ports(port_count, threshold):
    # returns whether distinct destination-port count meets threshold
    return port_count >= threshold