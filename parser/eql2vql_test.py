import eql2vql
import run_query
import os.path
import argparse
import collections
import tempfile
import providers
import testutils

parser = argparse.ArgumentParser(description='Run test suite.')
parser.add_argument('tests', nargs='*', help='Tests to run')
parser.add_argument('--update', action="store_true", help='Update fixtures')
parser.add_argument('--verbose', action="store_true", help='Verbose')
parser.add_argument('--testdir', help='Store generated yaml in this directory')

class EVTXTestSuite:
    """Test specific EQL queries one at the time."""

    TEST_CASES = [{
        "name": "RegistryKeyCreateValueSet",
        "rule": "testdata/testcases/privilege_escalation_rogue_windir_environment_var.toml",
        "sample": "testdata/EVTX-ATTACK-SAMPLES/Sysmon_UACME_34.evtx",
    }]

    provider = providers.SysmonEVTXLogProvider

    def RunTest(self, tests=None, update=False,
                verbose=False, testdir=None):
        failures = []
        try:
            for test in self.TEST_CASES:
                if tests and test['name'] not in tests:
                    continue

                testutils.RunTestWithProvider(
                    test["name"], test["rule"], test["sample"],
                    self.provider, update=update, verbose=verbose,
                    testdir=testdir)
        except Exception as e:
            failures.append(e)

        if failures:
            raise failures[0]

class SecurityDatasetTestSuite(EVTXTestSuite):
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

    provider = providers.SecurityDatasetTestProvider


if __name__ == "__main__":
    args = parser.parse_args()

    SecurityDatasetTestSuite().RunTest(args.tests, args.update,
                                       verbose=args.verbose,
                                       testdir=args.testdir)
    EVTXTestSuite().RunTest(args.tests, args.update,
                            verbose=args.verbose,
                            testdir=args.testdir)
