import query_ast
import argparse
import toml
import sysmon
import os
import re
import sys
import etw_provider
import providers
import dumper

import debug

from debug import Debug

class InvalidFileException(Exception):
    def __init__(self, filename, e):
        self.filename = filename
        self.e = e

    def __str__(self):
        return "Unable to parse %s: %s " % (self.filename, self.e)


parser = argparse.ArgumentParser(
    description='Convert EQL detection rules to a VQL artifact.')

parser.add_argument("-p", "--provider", type=str,
                    choices=[
                        "SysmonEVTXLogProvider",
                        "SysmonETWProvider",
                    ],
                    default="SysmonEVTXLogProvider",
                    help="Name of provider to use")

parser.add_argument("-v", "--verbose", action='store_true',
                    help="Enable verbose messages.")

parser.add_argument("-o", "--output", type=str, required=True,
                    help="Output file to write on")

parser.add_argument('files', metavar='N', type=str, nargs='+',
                    help='EQL TOML files to parse')

parser.add_argument('--exclude_regex',
                    help='Exclude rules that match this regex')


def GetAnalyzer(filename, exclude_regex):
    with open(filename) as fd:
        try:
            description = toml.loads(fd.read())
        except Exception as e:
            raise InvalidFileException(filename, e)

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

    if name == "SysmonETWProvider":
        return etw_provider.SysmonETWProvider

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
            Debug("Unable to load %s: %s" % (f, e))

    if not analyzers:
        Debug("No valid EQL rules loaded")
        return ""

    p = provider(analyzers)
    artifact = p.Render()
    print("Created artifact %r with %s detections" % (p.name, len(p.analyzers)))
    return dumper.DumpAsYaml(artifact)


if __name__ == "__main__":
    args = parser.parse_args()
    exclude_regex = None
    if args.exclude_regex:
        exclude_regex = re.compile(args.exclude_regex)

    debug.DEBUG = args.verbose

    with open(args.output, "w+") as fd:
        query = BuildArtifact(
            args.files, provider=GetProvider(args.provider),
            exclude_regex=exclude_regex)
        fd.write(query)
