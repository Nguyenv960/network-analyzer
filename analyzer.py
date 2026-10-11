import subprocess

command = [
    r"C:\Program Files\Wireshark\tshark.exe",
    "-r", r".\captures\baseline.pcapng",
    "-c", "5",
    "-T", "fields",
    "-e", "frame.number",
    "-e", "frame.time_relative",
    "-e", "frame.len",
    "-E", "header=y",
]

result = subprocess.run(
    command,
    capture_output=True,
    text = True,
    check = True,
)

lines = result.stdout.splitlines()
packet_rows = lines[1:]
packet_count = len(packet_rows)

print("Packets processed:", packet_count)