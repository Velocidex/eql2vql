import eql
import json
from debug import Debug


def Export(x):
    name = x.__class__.__name__
    handler = Dispatcher.get(name)
    if handler is None:
        Debug("No handler known for %s:" % name)
        Debug(x)
        # import pdb; pdb.set_trace()
        Debug(x)
    else:
        return handler(x)

Dispatcher = {
    "PipedQuery": lambda x: {
        "type": "PipedQuery",
        "first": Export(x.first),
        "pipes": [Export(i) for i in x.pipes],
    },
    "EventQuery": lambda x: {
        "type": "EventQuery",
        "event_type": Export(x.event_type),
        "query": Export(x.query),
    },
    "And": lambda x: {
        "type": "And",
        "terms": [Export(i) for i in x.terms],
    },
    "Not": lambda x: {
        "type": "Not",
        "term": Export(x.term),
    },
    "Or": lambda x: {
        "type": "Or",
        "terms": [Export(i) for i in x.terms],
    },
    "str": lambda x: x,
    "Comparison": lambda x: {
        "type": "Comparison",
        "left": Export(x.left),
        "right": Export(x.right),
        "comparator": Export(x.comparator),
    },
    "Field": lambda x: {
        "type": "Field",
        "base": x.base,
        "path": x.path,
    },
    "String": lambda x: x.value,
    "FunctionCall": lambda x: {
        "type": "FunctionCall",
        "name": x.name,
        "arguments": [Export(i) for i in x.arguments],
    },
    "IsNotNull": lambda x: {
        "type": "IsNotNull",
        "expression": Export(x.expr),
    },
    "InSet": lambda x: {
        "type": "InSet",
        "expression": Export(x.expression),
        "container": [Export(i) for i in x.container],
    },
    "Number": lambda x: {
        "type": "Number",
        "value": x.value,
    },
}

def parse_query_to_ast(query):
    with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
        ast = eql.parse_query(query)
        return Export(ast)
