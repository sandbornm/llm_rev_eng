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
        self.target_files = glob.glob(os.path.join(self.target_dir, '*', '*.bin'))

        if re_tool == "r2":
            self.handler = RadareHandler(self.target_dir)
        # add more handlers here

        self.cgpt_util = ChatGPTUtil()  # talk to chatGPT
        self.re_tool = re_tool  # which RE framework to get data from
        self.cmd_limit = cmd_limit  # max number of commands to run

        self.system_prompt_text = open(os.path.join(PROMPT_DIR, 'cmd_system_prompt.txt'), 'r').read().strip()


    def get_target_file_info(self, target_name: str) -> str:
        return open(os.path.join(DATA_DIR, target_name, f'{target_name}.file_info'), 'r').read()


    def get_target_name(self, target_file: str) -> str:
        return os.path.basename(target_file).split('.')[0]


    def run_cmd(self, cmd, args):
        
        #assert cmd in COMMANDS, f"Command {cmd} not found in COMMANDS."
        # todo add args error handling
        sys_prompt = {"role": "system", "content": self.system_prompt_text}
        user_prompt = {"role": "user", "content": cmd + "\n".join(args) if args else ""}

        messages = [sys_prompt, user_prompt]

        print(f"messages are: {messages}")

        print("calling get_chat_completion")
        #response = self.cgpt_util.get_chat_completion(messages)
        response = "{'next_cmd': 'summ', 'next_args': ' 'reasoning': 'bar'}"
        #print(f"response is: {response}")

        return response


    def save_result(result_dict, result_filename):
        with open(os.path.join(RESULT_DIR, result_filename), 'w') as f:
            json.dump(result_dict, f)


    def validate_response_json(self, response):
        try:
            response_json = json.loads(response)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return False

        required_keys = sorted(REQUIRED_RESPONSE_KEYS)
        response_keys = sorted(response_json.keys())
        if sorted(response_json.keys()) != sorted(REQUIRED_RESPONSE_KEYS):
            print(f"Required keys {[set(required_keys) - set(response_keys)]} missing in response.")
            return False

        return True


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

            r2_handler = RadareHandler(target_name)

            cmd_num = 1
            while cmd_num != self.cmd_limit:

                if cmd_num == 1:  # init
                    cmd = "plan"
                    args = None
                elif cmd_num == 2:  # init
                    cmd = "sift"
                    args = "strings"
                else:  # get next cmd from most recent json
                    next_cmd = self.get_next_cmd(target_name, cmd_num)
                    args = self.get_next_args(r2_handler, cmd_num, cmd)

                response = self.run_cmd(cmd_num, next_cmd, args)

                if not self.validate_response_json(response):
                    print(f"Invalid response: {response}, breaking")
                    break

                result_dict = {
                    "cmd_num": cmd_num,
                    "cmd": cmd,
                    "args": args,
                    "response": dict(response)
                }
                
                print(f"result dict is: {result_dict}")

                result_filename = f'{cmd_num}_{cmd}.json'
                self.save_result(result_dict, result_dir, result_filename)

                cmd_num += 1


    def get_next_cmd(self, target_name, cmd_num):
        prev_result = glob.glob(os.path.join(RESULT_DIR, target_name, f'{cmd_num-1}_*.json'))
        assert len(prev_result) == 1, f"Expected 1 result file, got {len(prev_result)}."
        
        next_cmd = str(prev_result['next_cmd'])
        assert next_cmd in COMMANDS, f"Command {next_cmd} not valid."
        return next_cmd
    

    def get_next_args(self, handler, cmd_num, prev_cmd):

        return handler._retrieve_args(cmd_num, prev_cmd)

