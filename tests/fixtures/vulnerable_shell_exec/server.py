import os
import subprocess


def run_command(cmd: str) -> str:
    # Unsanitized user input passed directly to shell
    os.system(cmd)
    result = subprocess.check_output(cmd, shell=True, text=True)
    return result
