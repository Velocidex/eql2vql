# Properly encode the artifact definition as YAML

import io

from ruamel import yaml
from ruamel.yaml.representer import RoundTripRepresenter
from collections import OrderedDict


class OrderedDictRepresenter(RoundTripRepresenter):
        pass

yaml.add_representer(
    OrderedDict, OrderedDictRepresenter.represent_dict,
    representer=OrderedDictRepresenter)

def DumpAsYaml(artifact):
    yaml_obj=yaml.YAML()
    yaml_obj.default_flow_style = False
    yaml.scalarstring.walk_tree(artifact)

    yaml_obj.Representer = OrderedDictRepresenter
    yaml_obj.default_style=None
    yaml_obj.default_flow_style = False

    s = io.StringIO()

    yaml_obj.dump(artifact, s)
    return s.getvalue()
