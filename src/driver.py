import os
from config import PROMPT_DIR, RESULT_DIR, DATA_DIR, REQUIRED_RESPONSE_KEYS, COMMANDS
from typing import List, Dict, Any
from chatgpt_util import ChatGPTUtil
from handlers import RadareHandler
import glob
import json




class LLMREDriver:

    def __init__(self, target_dir: str, re_tool: str, cmd_limit: int):

        print(f"init LLMREDriver with args: {target_dir}, {re_tool}, {cmd_limit}")
        assert os.path.exists(target_dir), f"File {target_dir} not found."
        self.target_dir = target_dir
        self.target_files = glob.glob(os.path.join(self.target_dir, '*.bin'))

        print(f"target files are: {self.target_files}")

        if re_tool == "r2":
            self.handler = RadareHandler(self.target_dir)
        # add more handlers here

        self.cgpt_util = ChatGPTUtil()  # talk to chatGPT
        self.re_tool = re_tool  # which RE framework to get data from
        self.cmd_limit = cmd_limit  # max number of commands to run

        self.system_prompt_text = open(os.path.join(PROMPT_DIR, 'cmd_system_prompt.txt'), 'r').read().strip()


    def get_target_file_info(self, target_name: str) -> str:
        file_info = open(os.path.join(DATA_DIR, target_name, f'{target_name}.file_info'), 'r').read()
        
        return str(file_info)


    def get_target_name(self, target_file: str) -> str:
        return os.path.basename(target_file).split('.')[0]


    def run_cmd(self, cmd, args):
        
        #assert cmd in COMMANDS, f"Command {cmd} not found in COMMANDS."
        # todo add args error handling
        sys_prompt = {"role": "system", "content": self.system_prompt_text}
        user_prompt = {"role": "user", "content": cmd + "\n" + args if args else ""}

        messages = [sys_prompt, user_prompt]

        print("=" * 30)
        print(f"Running command: {cmd}")
        print(f"args are: {user_prompt['content']}")

        #print(f"messages are: {messages}")

        print("calling get_chat_completion")
        response = self.cgpt_util.get_chat_completion(messages)[0]  # single response
        #response = "{'next_cmd': 'summ', 'next_args': ' 'reasoning': 'bar'}"
        print(f"response is: {response}")

        return response


    def save_result(result_dict, result_filename):
        with open(os.path.join(RESULT_DIR, result_filename), 'w') as f:
            json.dump(result_dict, f, indent=3)


    def is_valid_response(self, response):

        # convert response text to json from str
        assert isinstance(response, str), f"Response is not a string: {response}"

        try:
            data_dict = json.loads(response)  # Convert text to Python dictionary
            required_keys = set(REQUIRED_RESPONSE_KEYS)
            response_keys = set(data_dict.keys())
            if not required_keys.issubset(response_keys):
                missing_keys = required_keys - response_keys
                print(f"Missing keys: {missing_keys}")
                return False
            else:
                return True
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return False


    def run_analysis_loop(self):
        """
            main entry point of the LLM-RE driver. Run
            cmd_limit commands on each file in the target_dir
            and record the resulting information in json format
            in the result_dir for each target
        """

        for target_file in self.target_files[:1]:

            print(f"target file is: {target_file}")
            target_name = self.get_target_name(target_file)
            print(f"target name is: {target_name}")

            result_dir = os.path.join(RESULT_DIR, target_name, self.re_tool)
            if not os.path.exists(result_dir):
                os.makedirs(result_dir, exist_ok=True)
            print(f"result dir is: {result_dir}")

            self.handler._set_target(target_name)

            cmd_num = 1  # track cmd number
            cmd_history = []  # track past cmds 

            while cmd_num != self.cmd_limit:

                if cmd_num == 1:  # init
                    cmd = "plan"
                    args = self.get_target_file_info(target_name)
                elif cmd_num == 2:  # init
                    cmd = "sift"
                    args = "\n".join(["strings", self.handler._get_strings()])
                else:  # get next cmd from most recent json
                    cmd = self.get_next_cmd(target_name, cmd_num)
                    prev_cmd = cmd_history[-1]
                    args = self.get_next_args(cmd_num, prev_cmd)

                cmd_history.append(cmd)
                response = self.run_cmd(cmd, args)

                if not self.is_valid_response(response):
                    print(f"Invalid response: {response}, breaking")
                    break
                else:
                    result_dict = {
                        "cmd_num": cmd_num,
                        "cmd": cmd,
                        "args": args,
                        "response": json.loads(response)  # str to dict
                    }
                
                print(f"result dict is: {result_dict}")

                result_filename = f'{cmd_num}_{cmd}.json'
                self.save_result(result_dict, result_dir, result_filename)

                cmd_num += 1


    def get_next_cmd(self, target_name, cmd_num):
        prev_result = glob.glob(os.path.join(RESULT_DIR, target_name, f'{cmd_num-1}_*.json'))
        assert len(prev_result) == 1, f"Expected 1 result file, got {len(prev_result)}."
        
        next_cmd = str(prev_result['response']['next_cmd'])
        assert next_cmd in COMMANDS, f"Command {next_cmd} not valid."
        return next_cmd
    

    def get_next_args(self, cmd_num, prev_cmd):
        return self.handler._retrieve_args(cmd_num, prev_cmd)

