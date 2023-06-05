import subprocess
import json
import sys

binary_file = sys.argv[1]

ldd_output = subprocess.check_output(["ldd", binary_file]).decode("utf-8")

libraries = []
for line in ldd_output.splitlines():
    line = line.strip()
    if line:
        parts = line.split(" => ")
        if len(parts) == 2:
            library = {"library": parts[0].strip(), "path": parts[1].strip()}
            libraries.append(library)

bin_name = binary_file.split("/")[-1]
output_file = f"./{bin_name}_dynamic_deps.json"
with open(output_file, "w") as f:
    json.dump(libraries, f, indent=4)

print("Dynamic dependencies obtained. Results stored in", output_file)
