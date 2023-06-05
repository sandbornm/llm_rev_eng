import r2pipe
import json
import sys
import os

def depgraph(bin_path, func):
    r2 = r2pipe.open(bin_path, func)
    r2.cmd("aaa")
    graph_data = r2.cmdj("agaJ @ " + func)
    return graph_data

if __name__ == "__main__":
    bin_path = sys.argv[1]
    assert os.path.isfile(bin_path), f"File {bin_path} not found."
    func = sys.argv[2]
    graph_data = depgraph(func)
    with open(func + '_depgraph.json', 'w') as f:
        json.dump(graph_data, f, indent=4)
