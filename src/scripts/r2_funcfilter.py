import r2pipe
import json
import subprocess
import os
import sys

def interesting_functions(bin_path, threshold=5):
    # threshold is the minimum number of xrefs to consider a function interesting
    r2 = r2pipe.open(bin_path)
    r2.cmd("aaa")
    functions = r2.cmdj("aflj")

    for function in functions:
        xrefs = r2.cmdj(f"axtj @ {function['name']}")
        if len(xrefs) > threshold:
            yield function['name']

def run_scripts(bin_path, functions):
    for func in functions:
        subprocess.run(["python3", "r2_depgraph.py", bin_path, func])
        subprocess.run(["python3", "r2_xrefs.py", bin_path, func])

if __name__ == "__main__":
    bin_path = sys.argv[1]
    assert os.path.isfile(bin_path), f"File {bin_path} not found."
    functions = interesting_functions(bin_path)
    run_scripts(bin_path, functions)
