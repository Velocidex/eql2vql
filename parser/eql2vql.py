import query_ast
import argparse
import toml
import sysmon
import os
import sys
import providers
import dumper

from debug import Debug



parser = argparse.ArgumentParser(
    description='Convert EQL detection rules to a VQL artifact.')

parser.add_argument("--provider", type=str, default="SysmonEVTXLogProvider",
                    help="Name of provider to use")

parser.add_argument('files', metavar='N', type=str, nargs='+',
                    help='EQL TOML files to parse')

def GetAnalyzer(filename):
    with open(filename) as fd:
        description = toml.loads(fd.read())
        query = description["rule"]["query"]
        name = description["rule"]["name"]
        ast = query_ast.parse_query_to_ast(query)
        sysmon_engine = sysmon.SysmonMatcher(name, query)
        sysmon_engine.Visit(ast)

        return sysmon_engine

def GetProvider(name):
    if name == "SysmonEVTXLogProvider":
        return providers.SysmonEVTXLogProvider

    if name == "SecurityDatasetTestProvider":
        return providers.SecurityDatasetTestProvider

    raise RuntimeError("Unknown provider %s" % name)


def BuildArtifact(files, provider=providers.SysmonEVTXLogProvider):
    analyzers = []

    for f in files:
        try:
            sysmon_engine = GetAnalyzer(f)
            analyzers.append(sysmon_engine)
        except Exception as e:
            Debug("Unable to load %s: %s" % (f, e))

    p = provider(analyzers)
    artifact = p.Render()
    return dumper.DumpAsYaml(artifact)


if __name__ == "__main__":
    args = parser.parse_args()
    print(BuildArtifact(args.files, provider=GetProvider(args.provider)))
