def check_packet_burst(summary, threshold):
    return summary["packet_count"] >= threshold

def check_syn_volume(count, threshold):
    return count >= threshold

# Did one source send SYN-W/O-ACK packets to at least an x 
# number of distinct TCP ports on same destination with chosen time window?
def check_distinct_ports(port_count, threshold):
    return port_count >= threshold