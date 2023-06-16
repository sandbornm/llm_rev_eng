
from config import RESULT_DIR, TARGET_DIR
from driver import LLMREDriver
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run LLM-RE on a target binary.')
    parser.add_argument('--target_dir', type=str, help='target binary name')
    parser.add_argument('--cmd_limit', type=int, default=10, help='command limit for each target binary')
    parser.add_argument('--re_tool', type=str, default="re", help='re tool to use for LLM-RE')

    args = parser.parse_args()

    print(args)

    llm_driver = LLMREDriver(args.target_dir, args.re_tool, args.cmd_limit)

    # call run_analysis_loop on llm_driver (will make openai api calls which costs money)