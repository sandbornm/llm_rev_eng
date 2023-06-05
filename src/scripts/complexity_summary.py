import r2pipe
import collections

def extract_cfg(filename):
    r2 = r2pipe.open(filename)
    r2.cmd("aaa")  # Analyze the binary
    cfg = r2.cmdj("agj")  # Get the Control Flow Graph as JSON
    print(cfg[0])  # print the information of the first function in the CFG
    r2.quit()
    return cfg

def compute_cyclomatic_complexity(cfg):
    def is_branch_instruction(op):
        return op['type'] in ['jmp', 'cjmp', 'call', 'ucall', 'ret', 'ujmp']

    nodes = sum(len(func['blocks']) for func in cfg)
    edges = sum(sum(1 for op in block['ops'] if is_branch_instruction(op)) for func in cfg for block in func['blocks'])
    complexity = edges - nodes + 2 * len(cfg)
    return complexity



def compute_halstead_complexity(filename):
    r2 = r2pipe.open(filename)
    r2.cmd("aaa")  # Analyze the binary
    halstead = r2.cmdj("e halstead")
    r2.quit()
    return halstead

def generate_instruction_histogram(filename):
    r2 = r2pipe.open(filename)
    r2.cmd("aaa")  # Analyze the binary
    histogram = collections.Counter()
    for instr in r2.cmdj("pij 0 @ 10000"):
        mnemonic = instr.get("disasm", {}).get("mnemonic", "")
        histogram[mnemonic] += 1
    r2.quit()
    return histogram

# Example usage
binary_file = '/Users/michael/GradSchool/Summer2023/Linux-Malware-Samples/ff2a39baf61e34f14f9c49c27faed07bdd431605b3c845ab82023c39589e6798'
cfg = extract_cfg(binary_file)
cyclomatic_complexity = compute_cyclomatic_complexity(cfg)
halstead_complexity = compute_halstead_complexity(binary_file)
instruction_histogram = generate_instruction_histogram(binary_file)

print("Cyclomatic Complexity:", cyclomatic_complexity)
print("Halstead Complexity:", halstead_complexity)
print("Instruction Histogram:")
for instruction, count in instruction_histogram.items():
    print(f"{instruction}: {count}")
