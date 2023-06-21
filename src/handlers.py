
import os
from config import DATA_DIR, RESULT_DIR
from typing import List, Dict, Any, Union
import glob
import json


class RadareHandler:
    """
        retrieve relevant arguments for the current target so
        that when we get a response with specified next args and next commands
        we can obtain the necessary information to run the next command. 
        We will need a class for each supported RE tool.
    """
    def __init__(self, target_dir: str):
        self.target_dir = target_dir

    def _set_target(self, target_name: str):
        print(f"(handler) setting target to {target_name}")
        self.target_name = target_name

    def _retrieve_args(self, cmd_num, prev_cmd) -> List[str]:
        """
            given the target name and the command number, retrieve the arguments
            from the relevant files based on the command definition given in the prompt

            target_name and cmd_num provide the information to the relevant files,
            and the next_cmd and next_arg field in this result json file
            will inform which data needs to be fetched for the next command, given 
            the next command and its arguments.
        """
        with open(os.path.join(RESULT_DIR, self.target_name, f'{cmd_num}_{prev_cmd}.json'), 'r') as f:
            prev_result = json.load(f)

        next_cmd = prev_result['response']['next_cmd']
        next_args = prev_result['response']['next_args']

        args = next_args.split(' ')

        if next_cmd == "sift":
            stype = args[0]
            # get the list of strings or functions to filter, based on the value of stype
            # if stype == "strings":
            #     print("get strings")
            # elif stype == "functions":
            #     print("get functions")
            filled_args = "\n".join([stype, self.get_data(stype)])

        else:  # all other commands currently require a single function information
            func_id, code_format = args
            # get the function in the specified format
            filled_args = "\n".join([func_id, code_format, self.get_function_format(func_id, code_format)])
        
        return filled_args


    def _get_function_disasm(self, func_id: str) -> str:
        """ 
            given a function id, return the disassembly of the function as a string
        """
        func_disasm_lst = []

        with open(os.path.join(DATA_DIR, self.target_name, "r2", "func_disasm", f'{func_id}_disasm.json'), 'r') as f:
            disasm_str = f.readlines()

        disassembly_data = json.loads(disasm_str)

        for entry in disassembly_data:
            func_disasm_lst.append(entry["disasm"])
            # add more data from the disasm file here

        return "\n".join(func_disasm_lst)
        

    def _get_function_decomp(self, func_id: str) -> str:
        """
            given function id, return the decompiled code of the function as a string
        """
        func_decomp_lst = []

        with open(os.path.join(DATA_DIR, self.target_name, "r2", "nonempty_func_decomps", f'{func_id}_decomp.json'), 'r') as f:
            decomp_str = f.readlines()

        disassembly_data = json.loads(decomp_str)

        for entry in disassembly_data:
            func_decomp_lst.append(entry["disasm"])
            # add more data from the disasm file here

        return "\n".join(func_decomp_lst)



    def get_function_format(self, func_id: str, code_format: str = "asm") -> str:
        """
            given a function id, return the function in the specified format,
            which is either asm, decompiled code, or bytecode
        """

        assert code_format in ["asm", "decomp"], f"unrecognized code format: {code_format}"

        if code_format == "asm":
            return self._get_function_disasm(self.target_name, func_id)
        elif code_format == "decomp":
            return self._get_function_decomp(self.target_name, func_id)


    def _get_strings(self) -> str:
        # /Users/michael/GradSchool/Summer2023/llm_rev_eng/data/ls/r2/strings.json
        with open(os.path.join(DATA_DIR, self.target_name, "r2", "strings.json"), 'r') as f:
            strings_json = json.load(f)
        
        strings_list_as_str = '\n'.join([entry["string"] for entry in strings_json])

        return strings_list_as_str

    def _get_functions(self) -> str:
        with open(os.path.join(DATA_DIR, self.target_name, "r2", "functions.json"), 'r') as f:
            functions_json = json.load(f)

        func_list_as_str = '\n'.join([entry["name"] for entry in functions_json])
        
        return func_list_as_str


    def get_data(self, stype: str) -> str:
        """
            given a type of data to sift, return the list of strings or functions
            to filter
        """
        assert stype in ["strings", "functions"], f"unrecognized data type: {stype}"

        if stype == "strings":
            return self._get_strings(self.target_name)
        elif stype == "functions":
            return self._get_functions(self.target_name)
