import eql2vql
import run_query
import os.path
import yaml
import argparse
import collections


FIXTURES = "testdata/fixtures/"

parser = argparse.ArgumentParser(description='Run test suitr.')
parser.add_argument('tests', nargs='*', help='Tests to run')

ProcessColumns = [
    "EventData.UtcTime",
    "EventData.Image",
    "EventData.ParentImage",
    "EventData.CommandLine",
    "EventData.User",
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

class EVTXTestSuite:
    """Test specific EQL queries one at the time."""

    TEST_CASES = [{
        "name": "Registry Key create + Value set",
        "rule": "testdata/testcases/privilege_escalation_rogue_windir_environment_var.toml",
        "sample": "testdata/EVTX-ATTACK-SAMPLES/Sysmon_UACME_34.evtx",
        "columns": RegistryColumns,
    }]

    def RunTest(self, tests=None):
        CONVERSION="""
        LET SysmonGenerator <= generate(name="Sysmon",
        query={
         SELECT *
         FROM parse_evtx(filename=FullPath)
        })
        """

        result = []
        for test in self.TEST_CASES:
            name = test["name"]
            if tests and name not in tests:
                continue

            print ("Running test %s" % name)

            sysmon_engine = eql2vql.ParseRule(test["rule"])
            columns = test.get("columns")
            if columns:
                sysmon_engine.SetColumns(columns)

            query = sysmon_engine.AnalysisQuery()
            result.append("query = %s" % query)

            query = CONVERSION + query
            result.append("output = %s\n" % str(run_query.run_query(
                query,
                format="json",
                env=dict(FullPath=os.path.abspath(test["sample"]))), "utf8"))

            check_fixture(name, result)

class SecurityDatasetTestSuite:
    TEST_CASES = [{
        "name": "Process rule 1",
        "rule": "testdata/testcases/lateral_movement_service_control_spawned_script_int.toml",
        "sample": "testdata/Security-Datasets/aptsimulator_cobaltstrike_2021-06-11T21081492.json",
        "columns": ProcessColumns,
    }, {
        "name": "Process rule 2",
        "rule": "testdata/testcases/defense_evasion_execution_lolbas_wuauclt.toml",
        "sample": "testdata/Security-Datasets/covenant_lolbin_wuauclt_createremotethread_2020-10-12183248.json",
        "columns": ProcessColumns,
    }, {
        "name": "Network rule: DNS",
        "rule": "testdata/testcases/command_and_control_encrypted_channel_freesslcert.toml",
        "sample": "testdata/Security-Datasets/psh_cmstp_execution_bypassuac_2020-10-2201543213.json",
        "columns": DNSColumns,
    }]

    def RunTest(self, tests):
        # Security Datasets are already flattened so they do not represent
        # correct EVTX structure. This query massages the fields so they do
        # provide into the original evtx structure. This is required to mock
        # the real evtx file so we can test our detection rules which will
        # operate on EVTX files directly.
        CONVERSION="""
        LET Events = SELECT parse_json(data=Line) AS EventData
        FROM parse_lines(filename=FullPath)

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
        result = []
        for test in self.TEST_CASES:
            name = test["name"]
            if tests and name not in tests:
                continue

            print ("Running test %s" % name)
            sysmon_engine = eql2vql.ParseRule(test["rule"])
            result.append("eql = %s" % sysmon_engine.eql)
            columns = test.get("columns")
            if columns:
                sysmon_engine.SetColumns(columns)

            query = sysmon_engine.AnalysisQuery()
            result.append("query = %s" % query)
            output = run_query.run_query(
                CONVERSION + query,
                format="json",
                env=dict(FullPath=os.path.abspath(test["sample"])))

            result.append("output = %s" % str(output, "utf8"))

            check_fixture(name, result)

def check_fixture(name, result):
    new_data = "\n\n".join(result)
    filename = os.path.join(FIXTURES, name + ".txt")

    try:
        with open(filename) as fd:
            fixture_data = fd.read()
    except Exception as e:
        with open(filename, "w+") as fd:
            fd.write(new_data)
        raise e

    if fixture_data != new_data:
        print("Fixture failed for " + name)
        with open(filename, "w+") as fd:
            fd.write(new_data)

if __name__ == "__main__":
    args = parser.parse_args()

    SecurityDatasetTestSuite().RunTest(args.tests)
    EVTXTestSuite().RunTest(args.tests)
