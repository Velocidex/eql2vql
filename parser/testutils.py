"""Run test cases against the fixtures.

This test harness builds new artifacts using the provider and the toml
rules and then launches Velociraptor against the provided sample
file. The result is compared with the fixture.

"""

import providers
import eql2vql
import tempfile
import os
import run_query

FIXTURES = "testdata/fixtures/"

def RunTestWithProvider(name, rule, sample, provider, update=False):
    result = []

    artifact = eql2vql.BuildArtifact([rule], provider=provider)
    print("Testing %s with test file %s" % (name, sample))

    with tempfile.TemporaryDirectory() as tmpdirname:
        with open(os.path.join(tmpdirname, "test.yaml"), "w+") as fd:
            fd.write(artifact)

        result = ["artifact = %s" % artifact]
        arg_name = provider.parameters[0]["name"]
        output = run_query.collect_artifact(
            "Windows.Sysmon.Detection",
            tmpdirname, env={
                arg_name: os.path.abspath(sample)
            })

        result.append("output = %s" % str(output, "utf8"))
        check_fixture(name, result, update=update)


def check_fixture(name, result, update=False):
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
        if update:
            print("Updating fixture %s" % name)
            with open(filename, "w+") as fd:
                fd.write(new_data)

        raise RuntimeError("Fixture failed for " + name)

    else:
        print("Test %s PASSED" % name)
