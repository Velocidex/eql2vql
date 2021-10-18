import eql2vql
import run_query
import os.path
import yaml
import argparse
import collections
import tempfile
import providers
import testutils

parser = argparse.ArgumentParser(description='Run test suite.')
parser.add_argument('tests', nargs='*', help='Tests to run')
parser.add_argument('--update', action="store_true", help='Update fixtures')

class EVTXTestSuite:
    """Test specific EQL queries one at the time."""

    TEST_CASES = [{
        "name": "RegistryKeyCreateValueSet",
        "rule": "testdata/testcases/privilege_escalation_rogue_windir_environment_var.toml",
        "sample": "testdata/EVTX-ATTACK-SAMPLES/Sysmon_UACME_34.evtx",
    }]

    def RunTest(self, tests=None, update=False):
        for test in self.TEST_CASES:
            testutils.RunTestWithProvider(
                test["name"], test["rule"], test["sample"],
                providers.SysmonEVTXLogProvider,
                update=update)

class SecurityDatasetTestSuite:
    TEST_CASES = [{
        "name": "ProcessRule1",
        "rule": "testdata/testcases/lateral_movement_service_control_spawned_script_int.toml",
        "sample": "testdata/Security-Datasets/aptsimulator_cobaltstrike_2021-06-11T21081492.json",
    }, {
        "name": "ProcessRule2",
        "rule": "testdata/testcases/defense_evasion_execution_lolbas_wuauclt.toml",
        "sample": "testdata/Security-Datasets/covenant_lolbin_wuauclt_createremotethread_2020-10-12183248.json",
    }, {
        "name": "NetworkRule-DNS",
        "rule": "testdata/testcases/command_and_control_encrypted_channel_freesslcert.toml",
        "sample": "testdata/Security-Datasets/psh_cmstp_execution_bypassuac_2020-10-2201543213.json",
    }]

    def RunTest(self, tests=None, update=False):
        for test in self.TEST_CASES:
            testutils.RunTestWithProvider(
                test["name"], test["rule"], test["sample"],
                providers.SecurityDatasetTestProvider,
                update=update)


if __name__ == "__main__":
    args = parser.parse_args()

    SecurityDatasetTestSuite().RunTest(args.tests, args.update)
    EVTXTestSuite().RunTest(args.tests, args.update)
