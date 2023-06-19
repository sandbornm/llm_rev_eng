import r2pipe
import json
import sys
import os




def save_json(data, outfile):
    with open(outfile, "w") as f:
        json.dump(data, f, indent=4)

binary_path = sys.argv[1]
output_dir = sys.argv[2]

assert os.path.isfile(binary_path), f"File {binary_path} not found."
assert os.path.isdir(output_dir), f"Directory {output_dir} not found."

r2 = r2pipe.open(binary_path)

r2.cmd("aaa")

binary_info = json.loads(r2.cmd("ij"))
binary_info_filename = output_dir + "/binary_info.json"
save_json(binary_info, binary_info_filename)

functions = json.loads(r2.cmd("aflj"))
function_filename = output_dir + "/functions.json"
print(f"functions type is {type(functions)} with length {len(functions)}")
save_json(functions, function_filename)

imports = json.loads(r2.cmd("iij"))
import_filename = output_dir + "/imports.json"
save_json(imports, import_filename)

exports = json.loads(r2.cmd("iEj"))
export_filename = output_dir + "/exports.json"
save_json(exports, export_filename)

sections = json.loads(r2.cmd("iSj"))
sections_filename = output_dir + "/sections.json"
save_json(sections, sections_filename)

header = json.loads(r2.cmd("ihj"))
header_filename = output_dir + "/header.json"
save_json(header, header_filename)

strings = json.loads(r2.cmd("izj"))
strings_filename = output_dir + "/strings.json"
save_json(strings, strings_filename)

cfg = json.loads(r2.cmd("agj"))
cfg_filename = output_dir + "/cfg.json"
save_json(cfg, cfg_filename)


func_list = [f["name"] for f in functions]

# function level CFGs
func_cfg_dir = output_dir + "/nonempty_func_cfgs"
os.makedirs(func_cfg_dir, exist_ok=True)
cfg_count = 0

for func in func_list:
    func_cfg = r2.cmd("agaj @ " + func)
    if json.loads(func_cfg)["nodes"]:
        cfg_count += 1
        filename = func_cfg_dir + "/" + func + "_cfg.json"
        save_json(func_cfg, filename)
        #with open(filename, "w") as f:
        #    json.dump(func_cfg, f, indent=4)

print(f"non-empty func cfgs: {cfg_count}")

# function level decompilation
func_decomp_dir = output_dir + "/nonempty_func_decomps"
os.makedirs(func_decomp_dir, exist_ok=True)
decomp_count = 0

for func in func_list:
    decomp_func = r2.cmd("pdcj @ " + func)
    if decomp_func:
        decomp_count += 1
        filename = func_decomp_dir + "/" + func + "_decomp.json"
        save_json(decomp_func, filename)
        # with open(filename, "w") as f:
        #     json.dump(decomp_func)
    else:
        print(f"bad decompilation of func: {decomp_func}")

print(f"non-empty func decompilations: {decomp_count}")

# ghidra decompilation via radare
ghidra_decomp_dir = output_dir + "/nonempty_ghidra_decomps"
os.makedirs(ghidra_decomp_dir, exist_ok=True)
ghidra_count = 0

for func in func_list:
    ghidra_decomp = r2.cmd("pdgj @ " + func)
    if ghidra_decomp:
        ghidra_count += 1
        filename = ghidra_decomp_dir + "/" + func + "_ghidra_decomp.json"
        save_json(ghidra_decomp, filename)
        #with open(filename, "w") as f:
        #    json.dump(ghidra_decomp)
    else:
        print(f"bad ghidra decompilation of func: {ghidra_decomp}")

print(f"non-empty ghidra decompilations: {ghidra_count}")

# ghidra decompilation via radare
disasm_dir = output_dir + "/func_disasm"
os.makedirs(disasm_dir, exist_ok=True)
disasm_count = 0

for func in func_list:
    disasm = r2.cmd("pdj @ " + func)
    if disasm:
        print(type(disasm))
        disasm_count += 1
        filename = disasm_dir + "/" + func + "_disasm.json"
        save_json(disasm, filename)
        #with open(filename, "w") as f:
        #    json.dump(disasm)
    else:
        print(f"bad disassembly of func: {disasm}")

print(f"non-empty disassemblies: {disasm_count}")



r2.quit()