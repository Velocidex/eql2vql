# eql2vql - Leverage EQL based detection rules in Velociraptor

Transform EQL detection rules to VQL artifacts.

[Event Query Lanaguage](https://www.elastic.co/blog/introducing-event-query-language), EQL is a query language designed to identify specific detections. EQL assumes a specific schema in which the data is stored.

In a nutshell, EQL relies on the following process to load the event
data into Elastic backends:

1. The event logs are collected by (usually) Sysmon and stored in an
   EVTX file, depending on Sysmon configuration to specify which
   events should be collected and some first level data reduction.

2. Winlogbeat is run over the EVTX files, parsing the events.

3. Winlogbeat transforms each event into a elastic friendly schema
   (ECS). This transformation is implemented using this js file:

https://github.com/elastic/beats/blob/master/x-pack/winlogbeat/module/sysmon/config/winlogbeat-sysmon.js

4. Transformed events are sent to elastic where they are indexed.

5. EQL queries are applied on the backend searching for particular
   patterns in the collected data. These are the detections we care
   about.

## The Velociraptor difference

Velociraptor is an endpoint centric query engine using VQL as the
query language. VQL is able to query directly the true evidence source
(in this case sysmon EVTX files).

The main premise of Velociraptor's value proposition is to `push the
processing to the endpoint`. Instead of feeding all events from
thousands of endpoints to a central location and then using a high
performance database to churn though thousands of events per second,
Velociraptor simply runs the VQL query **on each endpoint
independently** and forwards only those high value detections to the
server. This solution scales very well because each endpoint is doing
it's own independent detection and does not need to forward **all**
events to the server. What does get forwarded is very high value
because it typically indicates a successfull detection!

## How EQL queries are applied in Velociraptor

The EQL queries available in the wild formulate specific patterns
known to represent attacker behaviors. Threat feeds often publish EQL
queries and many sources support EQL as a backend (e.g. Sigma can
directly produce EQL queries).

We would really like to be able to leverage this wealth of information
within Velociraptor in a couple of contexts:

1. In a triage we would like to remotely run queries on already stored
   EVTX files (e.g. in a hunt or triage capacity) in order to see if
   those files represent known attacker behavior.

2. Using Velociraptor's real time client monitoring queries we would
   like to use those same EQL based detections to monitor in real
   time, when attackers are active on the endpoint.

Since Velociraptor does not use a server backend to run detection, we
need to convert the EQL queries into VQL queries that can be run
directly on the endpoint. Luckily VQL is very flexible and most EQL
queries can be automatically transformed to a VQL query.

### The eql2vql project.

This project automatically converts multiple EQL based detection rules
into a `Detection Matrix`. The Detection Matrix is a set of VQL
queries that operate asynchronously on all the events to try and match
specific patterns. When a pattern is matched, the suspicious event is
surfaced as the VQL result set and forwarded to the server.

You can visualize the matrix as a two dimensional array - events on
one axis and rules on the other axis. When a rule matches an event we
get a positive detection which we report on.

The context in which the VQL query is run can be easily changed:

* A triage context simply searches for EVTX files, parses them and
  runs all the events through the detection matrix. This can be done
  remotely through Velociraptor's client/server model or using the
  Offline collector interactively from the command line.

* A monitoring artifact can be used to watch for sysmon events
  directly via ETW. Each event is sent through the detection matrix
  and matching events are forwarded to the server in near real time.

An important aspect to realize is that the detection matrix is
generated to target a specific source of information. For example, the
produced matrix can be targetted to work with sysmon.

The backend engine is designed to specifically target different
evidence sources. Currently we target sysmon but in future different
event sources may be designed.

This allows the same EQL rules to be converted to use multiple sources
of information - even sources which are not available from sysmon
(e.g. prefetch, USN etc).

### Data model

It makes sense for EQL to settle on a standardised schema
[ECS](https://www.elastic.co/guide/en/ecs/current/index.html) because
Elastic can be used to correlate events from multiple sources (e.g. network).

In Velociraptor we prefer to keep the original sources of evidence -
so in the case of Sysmon EVTX we just forward the EVTX event as is on
a match. I.e. Velociraptor has no intrinsic data model!

The EQL query will therefore be converted to a VQL query targetting
the original evidence source.
