# Overview

This repository contains scripts and utilities to facilitate LLM-assisted reverse engineering. The goal of this work is to provide an interface for an analyst to conduct preliminary static analysis of various software binaries with the ultimate goal of producing a plan for dynamic analysis.

There main components of this code are: 

- target entry point: directory of subject binaries to be analyzed
- prompts: input to LLM to enforce commands, their arguments, intended functionality, and expected output format
- the src directory contains the code to support llm-assisted RE tasks


# Setup

The dependencies are located in `requirements.txt`. Python 3 is assumed and is ideally within a virtual environment. 

It is also assumed that a valid `OPENAI_API_KEY` is set as an environment variable wherever the project is run from.


# Usage

the main entrypoint is the llm_re.py script. It takes a directory of binaries as input and optionally the maximum number of commands to be run for each binary as well as the re_tool that should be supported. The output of each command that is run is recorded in a folder under `data/target_name` where `target_name` is a single binary within the user-specified target directory.

# TODO

- [ ] add support for more/ simultaneous RE tools. Currently, only radare is supported, along with the Ghidra decompiler via a radare package. 

- [ ] complete the handler for radare to retrieve next args

- [ ] add commands for CFG traversal and function selection heuristics (e.g. data/code xref counts, function size, etc.)



