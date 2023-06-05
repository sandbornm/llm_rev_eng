import r2pipe
import json
import sys
import os

binary_file = sys.argv[1]

if not binary_file or not os.path.isfile(binary_file):
    print("Usage: python r2_cfg.py <binary_file>")
    sys.exit(1)

binary_name = os.path.splitext(os.path.basename(binary_file))[0]
output_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../data", binary_name)
os.makedirs(output_dir, exist_ok=True)

print("Obtaining CFG using radare2...")

r2 = r2pipe.open(binary_file)

r2.cmd("aaa")
cfg_json = r2.cmdj("agCj")

r2.quit()

cfg_path = os.path.join(output_dir, f"{binary_name}_cfg.json")
with open(cfg_path, "w") as f:
    json.dump(cfg_json, f)

print(f"CFG extraction complete. Result written to {cfg_path}")
