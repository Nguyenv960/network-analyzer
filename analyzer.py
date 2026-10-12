import subprocess
import shutil
from pathlib import Path

#checks os system to ensure that tshark is installed correctly
tshark_path = shutil.which("tshark")

if tshark_path is None:
    possible_paths = [
        Path(r"C:\Program Files\Wireshark\tshark.exe"),
        Path("/Applications/Wireshark.app/Contents/Macos/tshark")
    ]
    for path in possible_paths:
        if path.is_file():
            tshark_path = str(path)
            break

if tshark_path is None:
    raise FileNotFoundError(
        "TShark not found. Install Wireshark/Tshark or provide executable path"
    )

project_folder = Path(__file__).resolve().parent
capture_path = project_folder / "captures" / "baseline.pcapng"
command = [
    tshark_path,
    "-r", str(capture_path),
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
#empty-capture protection:
if packet_count == 0:
    raise SystemExit("No packets found in capture. Nothing to analyze")

#byte count loop
total_bytes = 0

for row in packet_rows:
    fields = row.split("\t")
    packet_length = int(fields[2])
    total_bytes = total_bytes + packet_length

first_fields = packet_rows[0].split("\t")
last_fields = packet_rows[-1].split("\t")

first_time = float(first_fields[1])
last_time = float(last_fields[1])

duration_seconds = last_time - first_time

avg_packets_per_second = packet_count / duration_seconds

#count dictionary
packets_by_second = {}

for row in packet_rows:
    fields = row.split("\t")
    packet_time = float(fields[1])
    second = int(packet_time)

    previous_count = packets_by_second.get(second, 0)
    packets_by_second[second] = previous_count + 1
#print statements
print("Packets processed:", packet_count)
print("Total frame bytes:", total_bytes)
print("Duration in seconds:", duration_seconds)
print(f"avg_packets_per_second:{avg_packets_per_second:.2f}")

print("Packets in windows 0:", packets_by_second.get(0,0))
print("Packets across all windows:", sum(packets_by_second.values()))

    #packets per second
print("\nPackets per one-second window:")
for second in sorted(packets_by_second):
    count = packets_by_second[second]
    print(f"Window {second} : {count} packets")

#find busiest window automatically
busiest_second = None
highest_packet_count = 0

for second in sorted(packets_by_second):
    count = packets_by_second[second]

    if count > highest_packet_count:
        highest_packet_count = count
        busiest_second = second
print("Busiest window:", busiest_second)
print("Packets in busiest window:", highest_packet_count)

window_end = busiest_second + 1

print(f"Wireshark filter: frame.timerelative >= {busiest_second} and frame.time_relative < {window_end}")