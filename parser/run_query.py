import subprocess
import os

def run_query(query, env=None, format="jsonl"):
    try:
        velociraptor_exe = os.environ["VELOCIRAPTOR"]
    except KeyError:
        raise RuntimeError("Please provide the velociraptor binary as the VELOCIRAPTOR environment string")


    if env is None:
        env = {}

    args = [velociraptor_exe, "query", query, "--format", format]
    for k, v in env.items():
        args.append("--env")
        args.append(k + "=" + v)

    return subprocess.check_output(args)
