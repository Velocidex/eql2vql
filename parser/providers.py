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

class BaseProvider:
    """Provide an artifact."""

    name = "Generic.EQLProvider"
    parameters = []

    generator = "Generator"
    generator_query = ""

    def __init__(self, analyzers):
        self.analyzers = analyzers

    def Render(self):
        """Render the entire artifact."""
        return OrderedDict(
            name=self.name,
            description=self.GetDescription(),
            parameters=self.parameters,
            sources=[OrderedDict(query=self.GetQuery())])

    def GetQuery(self):
        return (textwrap.dedent(self.generator_query) +
                textwrap.dedent(self.analyzers[0].AnalysisQuery())).strip()


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
        return ("Automated artifact for detection based on EQL.\n\n" + "\n".join(
            [x.eql for x in self.analyzers]))

    generator = "Generator"
    generator_query = """
      LET SysmonGenerator <= generate(name="Sysmon",
      query={
        SELECT * FROM foreach(row={SELECT FullPath FROM glob(globs=EVTXGlob)},
           query={
            SELECT *
            FROM parse_evtx(filename=FullPath)
          })
      })
    """


class SecurityDatasetTestProvider(SysmonEVTXLogProvider):
    """A provider for Security Datasets json files.

    These files are given by:

    Attack simulation in JSON files: https://github.com/OTRF/Security-Datasets.git

    Security Datasets are already flattened JSON files, so they do not
    represent correct EVTX structure. This provider massages the
    fields in the JSON files to reconstruct the original evtx
    structure making is suitable for the standard sysmon analysers.

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
    LET Events = SELECT parse_json(data=Line) AS EventData
    FROM parse_lines(filename=SecurityEventsJSONPath)

    LET SysmonGenerator <= generate(name="Sysmon",
    query={
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
    })
    """
