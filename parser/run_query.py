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


def collect_artifact(artifact, directory, env=None, format="jsonl"):
    try:
        velociraptor_exe = os.environ["VELOCIRAPTOR"]
    except KeyError:
        raise RuntimeError("Please provide the velociraptor binary as the VELOCIRAPTOR environment string")

    if env is None:
        env = {}

    args = [velociraptor_exe, "--definitions", directory,
            "artifacts", "collect", artifact]
    for k, v in env.items():
        args.append("--args")
        args.append(k + "=" + v)

    # print("Calling %s" % (args,))

    return subprocess.check_output(args)
