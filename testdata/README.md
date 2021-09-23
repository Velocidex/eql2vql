
# Test data

The files here come from two sources:

1. Various EQL Detection rules: https://github.com/elastic/detection-rules.git
2. Attack simulation in JSON files: https://github.com/OTRF/Security-Datasets.git
3. Sample EVTX files https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

Our goal in these tests is not to test the actual detection rules, but
rather test how these rules can be applied using Velociraptor to rely
in various aspects of EQL queries. Therefore we sometimes update the
detection rules to make them fit the simulated data more easily in
order to get a detection.

## Data sets pre-processing

The Security-Datasets files consist of JSON files which do not exactly
exactly reflect the EVTX structure. Specifically they are flattened in
such as way that all fields are hoisted to the top level.

In order to recreate the EVTX structure we need for testing, the test
harness reorgenizes the JSON data in the Security-Datasets files. This
is not needed with the EVTX-ATTACK-SAMPLES because they are already in
EVTX format.
