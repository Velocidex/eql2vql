import query_ast
import argparse
import toml
import sysmon
import os
import re
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

parser.add_argument('--exclude_regex',
                    help='Exclude rules that match this regex')


def GetAnalyzer(filename, exclude_regex):
    with open(filename) as fd:
        description = toml.loads(fd.read())
        query = description["rule"]["query"]
        name = description["rule"]["name"]
        if exclude_regex and exclude_regex.search(name):
            return

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


def BuildArtifact(
        files,
        provider=providers.SysmonEVTXLogProvider,
        exclude_regex=None):
    analyzers = []

    for f in files:
        try:
            sysmon_engine = GetAnalyzer(f, exclude_regex)
            if sysmon_engine:
                analyzers.append(sysmon_engine)
        except Exception as e:
            #import pdb; pdb.set_trace()
            Debug("Unable to load %s: %s" % (f, e))

    p = provider(analyzers)
    artifact = p.Render()
    return dumper.DumpAsYaml(artifact)


if __name__ == "__main__":
    args = parser.parse_args()
    exclude_regex = None
    if args.exclude_regex:
        exclude_regex = re.compile(args.exclude_regex)

    print(BuildArtifact(
        args.files, provider=GetProvider(args.provider),
        exclude_regex=exclude_regex))
