
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

    def _retrieve_args(self, target_name, cmd_num) -> Dict[str, str]:
        """
            given the target name and the command number, retrieve the arguments
            from the relevant files based on the command definition given in the prompt

            target_name and cmd_num provide the information to the relevant files,
            and the next_cmd and next_arg field in this result json file
            will inform which data needs to be fetched for the next command, given 
            the next command and its arguments.
        """
        pass