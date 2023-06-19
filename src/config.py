import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULT_DIR = os.path.join(ROOT_DIR, 'results')  # the LLM generated results
TARGET_DIR = os.path.join(ROOT_DIR, 'targets')  # target binaries organized by arch, each dir named after target
PROMPT_DIR = os.path.join(ROOT_DIR, 'prompts')  # prompt files
DATA_DIR = os.path.join(ROOT_DIR, 'data')  # background data organized by arch, each dir named after target

REQUIRED_RESPONSE_KEYS = [
    "next_cmd", "next_args", "reasoning"
]

COMMANDS = [
    "plan",
    "sift",
    "varname",
    "types",
    "ismain",
    "namefunc",
    "getsrc",
    "summ",
    "hypo"
]
