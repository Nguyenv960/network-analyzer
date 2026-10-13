import subprocess
import shutil
from pathlib import Path
from rules import check_packet_burst

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

if duration_seconds > 0:
    avg_packets_per_second = packet_count / duration_seconds
else:
    avg_packets_per_second = None

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

if avg_packets_per_second is None:
    print("Average packets per second: unavailable (zero-duration capture)")
else:
    print(f"Average packets per second:{avg_packets_per_second:.2f}")

print("Packets across all windows:", sum(packets_by_second.values()))

#find busiest window automatically
busiest_second = None
highest_packet_count = 0

for second in sorted(packets_by_second):
    count = packets_by_second[second]

    if count > highest_packet_count:
        highest_packet_count = count
        busiest_second = second

window_end = busiest_second + 1

#add traceability

first_frame = None
last_frame = None


for row in packet_rows:
    fields = row.split("\t")
    frame_number = int(fields[0])
    packet_time = float(fields[1])
    second = int(packet_time)

    if second == busiest_second:
        if first_frame is None:
            first_frame = frame_number
        last_frame = frame_number

busiest_window_percentage = (highest_packet_count/packet_count) * 100

#dictionary of results:
busiest_window_summary = {
    "start_second": busiest_second,
    "end_second"  : window_end,
    "packet_count": highest_packet_count,
    "percentage_of_capture": busiest_window_percentage,
    "first_frame": first_frame,
    "last_frame": last_frame,
}
def print_window_summary(summary):
    print("\nBusiest traffic window")
    print(f"Time: {summary['start_second']}-{summary['end_second']} seconds")
    print(f"Packets: {summary['packet_count']} ({summary['percentage_of_capture']:.2f}% of capture)")
    print(f"Frames: {summary['first_frame']}-{summary['last_frame']}")

print_window_summary(busiest_window_summary)

print(f"Wireshark filter: frame.time_relative >= {busiest_second} and frame.time_relative < {window_end}") 

#rules: packet burst threshold
packet_burst_threshold = 1000

burst_detected = check_packet_burst(busiest_window_summary, packet_burst_threshold)

if burst_detected:
    print("\n[ALERT] High packet volume")
    print(f"Reason: {busiest_window_summary["packet_count"]} packets in the busiest one-second window; threshold is {packet_burst_threshold}")
else:
    print("\n No packet-volume alert triggered")

