import query_ast
import argparse
import toml
import sysmon
import os
import sys
import providers
import dumper

parser = argparse.ArgumentParser(
    description='Convert EQL detection rules to a VQL artifact.')

parser.add_argument('files', metavar='N', type=str, nargs='+',
                    help='EQL TOML files to parse')

def GetAnalyzer(filename):
    with open(filename) as fd:
        description = toml.loads(fd.read())
        query = description["rule"]["query"]
        name = "'" + os.path.basename(filename) + "'"
        ast = query_ast.parse_query_to_ast(query)
        sysmon_engine = sysmon.SysmonMatcher(name, query)
        sysmon_engine.Visit(ast)

        return sysmon_engine

def BuildArtifact(files, provider=providers.SysmonEVTXLogProvider):
    analyzers = []

    for f in files:
        sysmon_engine = GetAnalyzer(f)
        analyzers.append(sysmon_engine)

    p = provider(analyzers)
    artifact = p.Render()
    return dumper.DumpAsYaml(artifact)


if __name__ == "__main__":
    args = parser.parse_args()
    print(BuildArtifact(args.files))
