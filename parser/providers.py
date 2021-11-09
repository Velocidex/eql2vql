# A provider is a source of events.

# Unlike traditional log forwarding software, Velociraptor has many
# ways to collecting information in many contexts. For example,
# process execution logs may be collected from ETW, WMI, eBPF and
# sysmon.
#
# The provider part of the query gets the events from various places
# and provides a stored query containing all the events formatted
# according to a particular scheme.
#
# The analyzer part of the query reads the events and applies an EQL
# test on it to produce a detection.
#
# So in other words, a provider does not depend on the specific EQL,
# but include the analyzer which implements the EQL.

from collections import OrderedDict
import textwrap

class BaseProvider(object):
    """Provide an artifact."""

    name = "Generic.EQLProvider"
    parameters = []
    analyzers = []

    def __init__(self, analyzers):
        self.analyzers = analyzers

    def Render(self):
        """Render the entire artifact."""
        return OrderedDict(
            name=self.name,
            type=self.type,
            description=self.GetDescription(),
            parameters=self.parameters,
            sources=[OrderedDict(query=self.GetQuery())])

    def GetGenerator(self):
        return ""

    def GetQuery(self):
        # The query consists of two parts:
        # 1. A generator query to produce the data
        # 2. All the definitions required by all the analyzers
        # 3. A query combining the analyzers into a larger query.

        result = [textwrap.dedent(self.GetGenerator())]
        definitions = {}
        names = []
        for analyzer in self.analyzers:
            analyzer.SetDefinitions(definitions)

            name, query = analyzer.AnalysisQuery()
            names.append(name)
            definitions[name] = query

        for k, v in sorted(definitions.items()):
            result.append(v)

        if len(self.analyzers) < 2:
            # Only one query, just SELECT it
            result.append("SELECT * FROM %s" % names[0])
        else:
            query = "SELECT * FROM chain(\n"
            for name in names:
                query += "   %s=%s,\n" % (name, name)
            query += "async=True)\n"

            result.append(query)

        return "\n\n".join([x.strip() for x in result])


class SysmonEVTXLogProvider(BaseProvider):
    """A provider that reads Sysmon events from Sysmon EVTX log files."""
    name = "Windows.Sysmon.Detection"
    parameters = [
        OrderedDict(
            name="EVTXGlob",
            description="Glob to search for EVTX files.",
            default=r"C:\Windows\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
        ),
    ]

    def GetDescription(self):
        rules = []
        for x in self.analyzers:
            rules.append("### %s\n```\n%s\n```\n" % (
                x.detection, x.eql.strip()))

        return ("Automated artifact for detection based on EQL.\n\n" + "\n".join(rules))

    def GetGenerator(self):
        # Wait 500ms before extracting events to let all the listeners start.
        return """
          LET SysmonGenerator = generate(name="Sysmon",
          query={
            SELECT * FROM foreach(row={SELECT FullPath FROM glob(globs=EVTXGlob)},
               query={
                SELECT *
                FROM parse_evtx(filename=FullPath)
              })
          }, delay=500)
        """


class SecurityDatasetTestProvider(SysmonEVTXLogProvider):
    """A provider for Security Datasets json files.

    These files are given by:

    Attack simulation in JSON files: https://github.com/OTRF/Security-Datasets.git

    Security Datasets are already flattened JSON files, so they do not
    represent correct EVTX structure. This provider massages the
    fields in the JSON files to reconstruct the original evtx
    structure making is suitable for the standard sysmon analyzers.

    NOTE: This provider is mainly used in testing EQL rules against
    the Security-Datasets files.
    """
    parameters = [
        OrderedDict(
            name="SecurityEventsJSONPath",
            description="Path to the security events file.",
            default=r"Security-Datasets/aptsimulator_cobaltstrike_2021-06-11T21081492.json",
        ),
    ]

    generator_query = """
         SELECT
          dict(
             Provider=dict(
                Name=EventData.SourceName,
                Guid=EventData.ProviderGuid),
             EventID=dict(
                Value=EventData.EventID
             ),
             Level=EventData.Level,
             Task=EventData.Task,
             TimeCreated=dict(
               SystemTime=timestamp(string=EventData.TimeCreated).Unix
             ),
             Execution=dict(
               -- ProcessId=TargetProcessId
             ),
             Channel=EventData.Channel,
             Computer=EventData.Hostname,
             Security=dict(
               UserID="" -- This seems to be missing?
             )
            ) AS System, EventData,
          EventData.Message AS Message
          FROM Events
    """

    def GetGenerator(self):
        if False and len(self.analyzers) == 1:
            return textwrap.dedent("""
            LET Events = SELECT parse_json(data=Line) AS EventData
            FROM parse_lines(filename=SecurityEventsJSONPath)

            LET SysmonGenerator = %s""" % self.generator_query.strip())

        return textwrap.dedent("""
        LET Events = SELECT parse_json(data=Line) AS EventData
        FROM parse_lines(filename=SecurityEventsJSONPath)

        LET SysmonGenerator = generate(name="Sysmon",
        query={
        %s
        })
        """ % self.generator_query.strip())
