import toml
import os
import eql2vql
import sysmon


def runTest():
 base = "detection-rules/rules/windows/"
    for filename in os.listdir(base):
        if not filename.endswith(".toml"):
            continue

        print(filename)
        file_path = os.path.join(base, filename)
        with open(file_path) as fd:
            try:
                description = toml.loads(fd.read())
            except Exception:
                continue

        rule_type = description["rule"]["type"]
        if rule_type != "eql":
            continue

        try:
            query = description["rule"]["query"]
        except KeyError:
            continue

        if "sequence" in query:
            continue

        try:
            sysmon_engine = eql2vql.ParseRule(file_path)
            print(sysmon_engine.AnalysisQuery(), flush=True)
        except sysmon.UnknownCategory:
            pass

if __name__ == "__main__":
    runTest()
