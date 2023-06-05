import r2pipe
import json
import sys
import os

def crossref(bin_path, func):
    r2 = r2pipe.open(bin_path)
    r2.cmd("aaa")
    xref_data = r2.cmdj("axtj @ " + func)
    return xref_data

if __name__ == "__main__":
    bin_path = sys.argv[1]
    assert os.path.isfile(bin_path), f"File {bin_path} not found."
    func = sys.argv[2]
    xref_data = crossref(bin_path, func)
    with open(func + '_crossref.json', 'w') as f:
        json.dump(xref_data, f, indent=4)
