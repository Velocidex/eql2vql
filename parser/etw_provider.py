from providers import BaseProvider
from collections import OrderedDict


class SysmonETWProvider(BaseProvider):
    """A provider that reads events from Sysmon EWT source for real time detection."""
    name = "Windows.Sysmon.EventDetection"
    type = "CLIENT_EVENT"
    parameters = []

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
            SELECT dict(EventID=dict(Value=System.ID),
                        Timestamp=System.TimeStamp) AS System,
                   EventData
            FROM watch_etw(guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}')
            WHERE get(field="EventData")
          }, delay=500)
        """
