import query_ast
import argparse
import toml
import sysmon
import os

parser = argparse.ArgumentParser(
    description='Convert EQL detection rules to a VQL artifact.')

parser.add_argument('files', metavar='N', type=str, nargs='+',
                    help='EQL TOML files to parse')

def ParseRule(filename):
    with open(filename) as fd:
        description = toml.loads(fd.read())
        query = description["rule"]["query"]
        name = "'" + os.path.basename(filename) + "'"
        ast = query_ast.parse_query_to_ast(query)
        sysmon_engine = sysmon.SysmonMatcher(name, query)
        sysmon_engine.Visit(ast)

        return sysmon_engine


if __name__ == "__main__":
    args = parser.parse_args()

    for f in args.files:
        sysmon_engine = ParseRule(f)
        print(sysmon_engine.Query())
