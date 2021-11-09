"""Implements EQL queries from sysmon sources.

EQL operates on events from the Elastic schema (ECS) as produced by
winlogbeat. Winlogbeat transforms the raw event to a ECS schema using
the transformations here

https://github.com/elastic/beats/blob/master/x-pack/winlogbeat/module/sysmon/config/winlogbeat-sysmon.js

This transformer attempts to reverse the transformation to produce VQL
queries that target the original event logs data. This avoids the need
for every raw event to be transformed prior to matching, as VQL
operates directly on the raw fields.

"""
from debug import Debug
import textwrap
import json
import re

class UnknownCategory(Exception):
    def __init__(self, category):
        self.category = category


class UnknownField(Exception):
    def __init__(self, key):
        self.key = key

    def __str__(self):
        return "No handler known for %s " % self.key


class InvalidAST(Exception):
    pass


def to_regex(expr):
    """Convert an eql glob like expression to a regex."""

    # Single \ needs to be doubled twice - once for VQL string and
    # once for regex.
    # First escape literals.
    res = expr.replace("\\", "\\\\\\\\", -1)

    res = res.replace("+", "\\\\+")
    res = res.replace(".", "\\\\.")
    res = res.replace("(", "\\\\(")
    res = res.replace(")", "\\\\)")

    # Now convert wildcards to regex
    res = res.replace("?", ".")
    return "^" + res.replace("*", ".*") + "$"

def quote(x):
   if " " in x:
       return "'" + x + "'"
   return x

def AsName(x):
    return "_" + re.sub("[^a-zA-Z]", "", x)

ProcessColumns = [
    "EventData.UtcTime",
    "EventData.Image",
    "EventData.ParentImage",
    "EventData.CommandLine",
    "EventData.User",
]

FileColumns = [
    "EventData",
]

LibraryColumns = [
    "EventData",
]

RegistryColumns = [
    "EventData.UtcTime",
    "EventData.EventType",
    "EventData.Image",
    "EventData.TargetObject",
    "EventData.Details",
]

DNSColumns = [
    "EventData.UtcTime",
    "EventData.QueryName",
    "EventData.Image",
    "protocol",
]


class SysmonMatcher:
    # The VQL definitions of the streams we will need. These will
    # build eql compatible streams for the different EQL log types.
    Preamble = {
        # Process related logs. Combine several event IDs into the
        # same generator.
        "process": dict(
            ProcessTypes="""
                LET ProcessTypes <= dict(`1`="start", `5`="stop")
            """,
            ProcessInfo="""
                LET ProcessInfo = generate(name="ProcessInfo", query={
                  SELECT *,
                         basename(path=EventData.ParentImage) AS ParentImageBase,
                         basename(path=EventData.Image) AS ImageBase,
                         commandline_split(command=EventData.CommandLine) AS CommandArgs,
                         get(item=ProcessTypes, field=str(str=System.EventID.Value)) AS event_type
                  FROM SysmonGenerator
                  WHERE System.EventID.Value in (1, 5)
               })
            """),

        "library": dict(
            LibraryInfo="""
                LET LibraryInfo = generate(name="LibraryInfo", query={
                  SELECT *, "load" AS action, "library" AS category
                  FROM SysmonGenerator
                  WHERE System.EventID.Value in 7
                })
            """),

        # File modification logs. Combine several event IDs into the
        # same generator.
        "file": dict(
            FileTypes="""
                LET FileTypes <= dict(`23`="deletion", `11`="creation")
            """,
            FileInfo="""
                LET FileInfo = generate(name="FileInfo", query={
                   SELECT *,
                          get(item=FileTypes, field=str(str=System.EventID.Value)) AS event_type
                   FROM SysmonGenerator
                   WHERE System.EventID.Value in (23, 11)
                })
            """),

        # Network logs. Combine several event IDs into the same
        # generator.
        "network": dict(
            NetworkInfo="""
                LET NetworkInfo = generate(name="NetworkInfo", query={
                  SELECT *, "dns" AS protocol
                  FROM SysmonGenerator
                  WHERE System.EventID.Value = 22
                })
            """),

        # Represent the value as a string. Sysmon encodes values as
        # hex, but eql seems to use integers.
        "registry": dict(
            ParseDetails="""
                LET ParseDetails(Details) = if(condition=Details =~ "[QD]WORD",
                then=str(str=atoi(string=parse_string_with_regex(string=Details,
                   regex='''(0x[0-9a-f]+)\\)$''').g1)),
                else=Details)
            """,
            NormalizeHive="""
                LET NormalizeHive(Path) = regex_transform(
                    key="hives", map=dict(
                      `^HKCR`="HKEY_CLASSES_ROOT", `^HKCU`="HKEY_CURRENT_USER",
                      `^HKLM`="HKEY_LOCAL_MACHINE", `^HKU`="HKEY_USERS"
                    ), source=Path)
            """,
            RegTypes=r"""
                LET RegTypes <= dict(`13`="value_set", `14`="rename", `12`="key_create")
                LET RegInfo = generate(name="RegInfo", query={
                  SELECT *,
                         NormalizeHive(Path=EventData.TargetObject) AS NormalizedTargetObject,
                         get(item=RegTypes, field=str(str=System.EventID.Value)) AS event_type,
                         ParseDetails(Details=EventData.Details) AS ValueData
                  FROM SysmonGenerator
                  WHERE System.EventID.Value in (12, 13, 14)
                })
                """),
    }

    # A mapping between EQL fields and sysmon fields as retrieved by
    # VQL
    FieldMap = {
        # For Sysmon Event ID 1
        # https://github.com/elastic/beats/blob/46d17b411cce465466daf163a1014155cc2d93b2/x-pack/winlogbeat/module/sysmon/config/winlogbeat-sysmon.js#L652
        "process|@timestamp": "EventData.UtcTime",
        "process|entity_id": "EventData.ProcessGuid",
        "process|pid": "EventData.ProcessId",
        "process|executable": "EventData.Image",
        "process|command_line": "EventData.CommandLine",
        "process|working_directory": "EventData.CurrentDirectory",
        "process|parent.entity_id": "EventData.ParentProcessGuid",
        "process|parent.pid": "EventData.ParentProcessId",
        "process|parent.executable": "EventData.ParentImage",
        "process|parent.command_line": "EventData.ParentCommandLine",
        "process|parent.name": "ParentImageBase",
        "process|parent.args": "commandline_split(command=EventData.ParentCommandLine)",
        "process|name": "ImageBase",

        "process|pe.company": "EventData.Company",
        "process|pe.description": "EventData.Description",
        "process|pe.file_version": "EventData.FileVersion",
        "process|pe.product": "EventData.Product",
        "process|pe.original_file_name": "EventData.OriginalFileName",
        "process|args_count": "len(list=commandline_split(command=EventData.CommandLine)) ",

        "host|os.name": "Windows",

        "event|type": "event_type",
        "process|args": "CommandArgs",
        "process|code_signature.subject_name": {
            "column": "Signature.Subject",
            "enrichment": "Signature",
        },
        "dll|code_signature.subject_name": "EventData.Signature",
        "dll|code_signature.status": "EventData.signatureStatus",

        "rule|name": "EventData.RuleName",

        "user|domain": "split(string=EventData.User, sep='''\\\\''')[0]",
        "user|id": "EventData.User",
        "user|name": "EventData.User",

        # Event 2 File creation time changed.
        "file|code_signature.signed": "EventData.Signed",
        "file|code_signature.valid": "EventData.Signed = 'Valid'",
        "file|extension": "split(string=EventData.TargetFilename, sep='''\\\\.''')[-1]",
        "file|path": "EventData.TargetFilename",
        "file|name": "basename(path=EventData.TargetFilename)",
        "file|directory": "dirname(path=EventData.TargetFilename)",
        "file|code_signature.subject_name": "EventData.Signature",
        "file|code_signature.status": "EventData.signatureStatus",

        # https://github.com/elastic/beats/blob/46d17b411cce465466daf163a1014155cc2d93b2/x-pack/winlogbeat/module/sysmon/config/winlogbeat-sysmon.js#L592
        "registry|path": "NormalizedTargetObject",
        "registry|data.strings": "ValueData",
        "registry|value": "ValueData",

        # Event ID 3 - Network connection detected.
        "network|direction": "if(condition=EventData.Initiated, then='egress', else='ingress')",
        "network|type": "if(condition=EventData.SourceIsIpv6, then='ipv6', else='ipv4')",

        "network|transport": "EventData.Protocol",
        "source|ip": "EventData.SourceIp",
        "source|domain": "EventData.SourceHostname",
        "source|port": "EventData.SourcePort",
        "destination|ip": "EventData.DestinationIp",
        "destination|address": "EventData.DestinationIp",
        "destination|domain": "EventData.DestinationHostname",
        "destination|port": "EventData.DestinationPort",
        "network|protocol": "protocol",

        "dns|question.name": "EventData.QueryName",

        # Library - event id 7
        "event|action": "action",
        "event|category": "category",
        "dll|name": "EventData.ImageLoaded",
    }

    EnrichmentMap = {
        "event_type": "'start'",
        "Signature": '''authenticode(file=EventData.Image)''',
    }

    def __init__(self, detection, eql):
        # What enrichment fields we need to add.
        self.enrichments = {}
        self.detection = detection
        self.eql = eql
        self.preamble = {}

        # Columns we will be selecting
        self.columns = ["*"]

        # Source we select from.
        self.source = ""

        # The WHERE clause to filter rows
        self.where = ""

    def SetColumns(self, columns):
        self.columns = columns

    def Query(self):
        # The total query is split into a collector query and a
        # detection query.
        return self.CollectorQuery() + self.AnalysisQuery()

    def getColumns(self):
        result = ["EventData || UserData AS _EventData", "System AS _System"]
        for c in self.columns:
            if "EventData" in c:
                c = c + " AS " + c.split(".")[-1]
            result.insert(0, c)
        return result

    def SetDefinitions(self, definitions):
        for k, preamble in self.preamble.items():
            preamble = textwrap.dedent(preamble)
            definitions[k] = preamble

    def AnalysisQuery(self):
        """ Return the analysis query for the rule."""
        columns = self.getColumns()
        columns.insert(0, quote(self.detection) + " AS Detection")

        name = AsName(self.detection)

        return name, r"""
LET %s = SELECT %s
FROM %s
WHERE %s """ % (name, ",\n       ".join(columns),
                self.source, self.where)

    def Visit(self, ast):
        if isinstance(ast, str):
            return "'" + ast + "'"

        if ast is None:
            raise InvalidAST()

        t = ast["type"]

        try:
            handler = getattr(self, t)
        except AttributeError:
            #import pdb; pdb.set_trace()
            raise UnknownField(t)

        return handler(ast)

    def PipedQuery(self, ast):
        # Visit the first element
        first = self.Visit(ast["first"])

        # We do not support pipes just yet
        return first

    def EventQuery(self, ast):
        event_type = ast["event_type"]
        # We only support Sysmom log sources

        if event_type == "process":
            self.source = "ProcessInfo"
            self.preamble.update(self.Preamble["process"])
            self.SetColumns(ProcessColumns)

        elif event_type == "library":
            self.source = "LibraryInfo"
            self.preamble.update(self.Preamble["library"])
            self.SetColumns(LibraryColumns)

        elif event_type == "file":
            self.source = "FileInfo"
            self.preamble.update(self.Preamble["file"])
            self.SetColumns(FileColumns)

        elif event_type == "registry":
            self.source = "RegInfo"
            self.preamble.update(self.Preamble["registry"])
            self.SetColumns(RegistryColumns)

        elif event_type == "network":
            self.source = "NetworkInfo"
            self.preamble.update(self.Preamble["network"])
            self.SetColumns(DNSColumns)

        else:
            raise UnknownCategory(
                "Unsupported event type for SysmonMatcher: " + event_type)

        self.where = self.Visit(ast["query"])

    def Not(self, ast):
        return " NOT " + self.Visit(ast["term"])

    def And(self, ast):
        value = []
        for term in ast["terms"]:
            value.append(self.Visit(term))

        if len(term) > 1:
            return " ( " + "\n  AND ".join(value) + " ) "

        return value[0]

    def InSet(self, ast):
        return (self.Visit(ast["expression"]) + " IN (" +
                ", ".join([self.Visit(i) for i in ast["container"]])) + " ) "

    def Or(self, ast):
        value = []
        for term in ast["terms"]:
            try:
                i = self.Visit(term)
            except UnknownField as e:
                #Debug("Skipping OR term for unsupported field " + e.key)
                raise UnknownField(e.key)

            value.append(i)

        if len(term) > 1:
            return " ( " + " OR ".join(value) + " ) "

        return value[0]

    def Field(self, ast):
        """Map between the field and the data source."""
        key = ast["base"] + "|" + ".".join(ast["path"])
        try:
            sub = self.FieldMap[key]
            if isinstance(sub, str):
                return sub

            if isinstance(sub, dict):
                enrichment = sub.get("enrichment")
                if enrichment:
                    self.enrichments[enrichment] = 1

                return sub["column"]

            return sub
        except KeyError:
            #import pdb; pdb.set_trace()
            raise UnknownField(key)

    def Comparison(self, ast):
        operator = self.OperatorMap.get(ast["comparator"])
        if operator == None:
            operator = ast["comparator"]

        return (self.Visit(ast["left"]) + " " +
                operator + " " + self.Visit(ast["right"]))

    OperatorMap = {
        # EQL -> VQL
        "==": "=",
    }

    def FunctionCall(self, ast):
        name = ast["name"]
        arguments = ast["arguments"]

        if name == "wildcard":
            if len(arguments) < 2:
                raise IOError("Expected two or more args for wildcard got %s" % arguments)

            # Figure out the regex from the wildcards
            regex = "|".join([to_regex(x) for x in arguments[1:]])
            arg0 = self.Visit(arguments[0])
            return arg0 + " =~ '" + regex + "'"

        if name == "match":
            if len(arguments) < 2:
                raise IOError("Expected two args for match got %s" % arguments)

            regex = "|".join(arguments[1:])

            return (self.Visit(arguments[0]) + " =~ '" + regex + "'")

        if name == "length":
            return " len(list="+ self.Visit(arguments[0]) + ") "

        raise IOError("Unknown FunctionCall " + name)

    def IsNotNull(self, ast):
        return " NOT " + self.Visit(ast["expression"])

    def Number(self, ast):
        return str(ast["value"])
