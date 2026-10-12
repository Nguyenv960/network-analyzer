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