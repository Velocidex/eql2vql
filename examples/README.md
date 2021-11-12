# Examples of eql2vql generation

These examples are compiled from https://github.com/elastic/detection-rules

### Windows.Sysmon.Detection

This artifact is designed to parse existing EVTX files and apply the
detection rules on them. You can use it in a hunt or specifically
collect from a machine.

You can regenerate them using
```
python3 parser/eql2vql.py -p SysmonEVTXLogProvider ~/projects/detection-rules/rules/windows/* -o Windows.Sysmon.Detection.yaml
```

### Windows.Sysmon.EventDetection

This is an event artifact designed to filter events from Symon in real
time, emitting any detections matching. You can install it using the
`Client Events` screen in Velociraptor.

Regenerate using
```
python3 parser/eql2vql.py -p SysmonETWProvider ~/projects/detection-rules/rules/windows/* -o Windows.Sysmon.EventDetection.yaml
```
