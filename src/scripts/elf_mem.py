import json
from elftools.elf.elffile import ELFFile

def get_mem_layout(binaryfile):
    mem_layout = []

    with open(binaryfile, 'rb') as f:
        elffile = ELFFile(f)

        for section in elffile.iter_sections():
            section_info = {
                "name": section.name,
                "size": section['sh_size'],
                "addr": section['sh_addr'],
                "type": section['sh_type'],
                "flags": section['sh_flags']
            }

            mem_layout.append(section_info)

    return mem_layout

if __name__ == "__main__":
    import sys
    binaryfile = sys.argv[1]

    mem_layout = get_mem_layout(binaryfile)

    print(json.dumps(mem_layout, indent=2))
