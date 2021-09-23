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

import json

class UnknownCategory(Exception):
    def __init__(self, category):
        self.category = category


class UnknownField(Exception):
    def __init__(self, key):
        self.key = key


def to_regex(expr):
    """Convert an eql glob like expression to a regex."""

    # Single \ needs to be doubled twice - once for VQL string and
    # once for regex.
    res = expr.replace("\\", "\\\\\\\\", -1)
    res = res.replace("?", ".")
    res = res.replace("+", "\\\\+")
    res = res.replace(".", "\\\\.")
    return res.replace("*", ".*")

class SysmonMatcher:
    # The VQL definitions of the streams we will need. These will
    # build eql compatible streams for the different EQL log types.
    Preamble = {
        # Process related logs. Combine several event IDs into the
        # same generator.
        "process": """
        LET ProcessTypes <= dict(`1`="start", `5`="stop")

        LET ProcessInfo = SELECT *,
          get(item=ProcessTypes, field=str(str=System.EventID.Value)) AS event_type
        FROM SysmonGenerator
        WHERE System.EventID.Value in (1, 5)
        """,

        "library": """
        LET LibraryInfo = SELECT *, "load" AS action, "library" AS category
        FROM SysmonGenerator
        WHERE System.EventID.Value in 7
        """,

        # File modification logs. Combine several event IDs into the
        # same generator.
        "file": """
        LET FileTypes <= dict(`23`="deletion", `11`="creation")

        LET FileInfo = SELECT *,
          get(item=FileTypes, field=str(str=System.EventID.Value)) AS event_type
        FROM SysmonGenerator
        WHERE System.EventID.Value in (23, 11)
        """,

        # Network logs. Combine several event IDs into the same
        # generator.
        "network": """
        LET NetworkInfo = SELECT *, "dns" AS protocol
        FROM SysmonGenerator
        WHERE System.EventID.Value = 22
        """,

        # Represent the value as a string. Sysmon encodes values as
        # hex, but eql seems to use integers.
        "registry": """
        LET ParseDetails(Details) = if(condition=Details =~ "[QD]WORD",
        then=str(str=atoi(string=parse_string_with_regex(string=Details,
           regex='''(0x[0-9a-f]+)\\)$''').g1)),
        else=Details)

        LET NormalizeHive(Path) = regex_transform(
            key="hives", map=dict(
              `^HKCR`="HKEY_CLASSES_ROOT", `^HKCU`="HKEY_CURRENT_USER",
              `^HKLM`="HKEY_LOCAL_MACHINE", `^HKU`="HKEY_USERS"
            ), source=Path)

        LET RegTypes <= dict(`13`="value_set", `14`="rename", `12`="key_create")
        LET RegInfo = SELECT *,
          get(item=RegTypes, field=str(str=System.EventID.Value)) AS event_type,
          ParseDetails(Details=EventData.Details) AS ValueData
        FROM SysmonGenerator
        WHERE System.EventID.Value in (12, 13, 14)
        """,
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
        "process|parent.name": "EventData.ParentImage",
        "process|parent.args": "EventData.ParentCommandLine",
        "process|name": "EventData.Image",

        "process|pe.company": "EventData.Company",
        "process|pe.description": "EventData.Description",
        "process|pe.file_version": "EventData.FileVersion",
        "process|pe.product": "EventData.Product",
        "process|pe.original_file_name": "EventData.OriginalFileName",
        "process|args_count": "len(list=commandline_split(command=EventData.CommandLine)) ",

        "host|os.name": "Windows",

        "event|type": "event_type",
        "process|args": "EventData.CommandLine",
        "process|code_signature.subject_name": {
            "column": "Signature.Subject",
            "enrichment": "Signature",
        },
        "dll|code_signature.subject_name": "EventData.Signature",
        "dll|code_signature.status": "EventData.signatureStatus",

        "rule|name": "EventData.RuleName",

        "user|domain": "split(path=EventData.User, sep='\\\\')[0]",
        "user|id": "EventData.User",
        "user|name": "EventData.User",

        # Event 2 File creation time changed.
        "file|code_signature.signed": "EventData.Signed",
        "file|code_signature.valid": "EventData.Signed = 'Valid'",
        "file|extension": "split(string=EventData.TargetFilename, sep='\\\\.')[-1]",
        "file|path": "EventData.TargetFilename",
        "file|name": "basename(path=EventData.TargetFilename)",
        "file|directory": "dirname(path=EventData.TargetFilename)",
        "file|code_signature.subject_name": "EventData.Signature",
        "file|code_signature.status": "EventData.signatureStatus",

        # https://github.com/elastic/beats/blob/46d17b411cce465466daf163a1014155cc2d93b2/x-pack/winlogbeat/module/sysmon/config/winlogbeat-sysmon.js#L592
        "registry|path": "NormalizeHive(Path=EventData.TargetObject)",
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
        self.preamble = []

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

    def AnalysisQuery(self):
        """ Return the analysis query for the rule."""
        columns = self.columns[:]
        columns.append(self.detection + " AS Detection")

        return "\n".join(self.preamble) + """
SELECT %s FROM %s
WHERE %s """ % (",".join(columns), self.source, self.where)

    def Visit(self, ast):
        if isinstance(ast, str):
            return "'" + ast + "'"

        t = ast["type"]

        try:
            handler = getattr(self, t)
        except AttributeError:
            print("No handler for %s" % t)
            import pdb; pdb.set_trace()
            return ""

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
            self.preamble.append(self.Preamble["process"])

        elif event_type == "library":
            self.source = "LibraryInfo"
            self.preamble.append(self.Preamble["library"])

        elif event_type == "file":
            self.source = "FileInfo"
            self.preamble.append(self.Preamble["file"])

        elif event_type == "registry":
            self.source = "RegInfo"
            self.preamble.append(self.Preamble["registry"])

        elif event_type == "network":
            self.source = "NetworkInfo"
            self.preamble.append(self.Preamble["network"])

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
                print("Skipping OR term for unsupported field " + e.key)
                continue

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

            return (self.Visit(arguments[0]) +
                    " =~ '" + regex + "'")

        if name == "match":
            if len(arguments) < 2:
                raise IOError("Expected two args for match got %s" % arguments)

            regex = "|".join(arguments[1:])

            return (self.Visit(arguments[0]) + " =~ '" + regex + "'")

        if name == "length":
            return " len(list="+ self.Visit(arguments[0]) + ") "

        import pdb; pdb.set_trace()
        raise IOError("Unknown FunctionCall " + name)

    def IsNotNull(self, ast):
        return " NOT " + self.Visit(ast["expression"])

    def Number(self, ast):
        return str(ast["value"])
