
from config import RESULT_DIR, TARGET_DIR
from driver import LLMREDriver
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run LLM-RE on a target binary.')
    parser.add_argument('--target-dir', type=str, help='folder of binaries to analyze')
    parser.add_argument('--cmd-limit', type=int, default=10, help='max number of commands for each binary')
    parser.add_argument('--re-tool', type=str, default="r2", help='re tool to use for LLM-RE')

    args = parser.parse_args()

    print(f"args.target_dir: {args.target_dir}")
    print(f"args.cmd_limit: {args.cmd_limit}")
    print(f"args.re_tool: {args.re_tool}")

    llm_driver = LLMREDriver(args.target_dir, args.re_tool, args.cmd_limit)

    # call run_analysis_loop on llm_driver (will make openai api calls which costs money)
    llm_driver.run_analysis_loop()