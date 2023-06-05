import json
import pefile

def get_mem_layout_pe(pefile_path):
    pe = pefile.PE(pefile_path)

    mem_layout = []
    for section in pe.sections:
        section_info = {
            "name": section.Name.decode().rstrip('\x00'),  # remove trailing null bytes
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": hex(section.Misc_VirtualSize),
            "size_of_raw_data": section.SizeOfRawData,
            "characteristics": hex(section.Characteristics)
        }

        mem_layout.append(section_info)

    return mem_layout

if __name__ == "__main__":
    import sys
    pe_file_path = sys.argv[1]

    mem_layout = get_mem_layout_pe(pe_file_path)

    print(json.dumps(mem_layout, indent=2))
