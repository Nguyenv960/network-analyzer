def check_packet_burst(summary, threshold):
    return summary["packet_count"] >= threshold

def check_syn_volume(count, threshold):
    return count >= threshold