"""
Secure pickle deserialization module.

This module provides a RestrictedUnpickler that only allows deserialization
of safe, whitelisted classes to prevent arbitrary code execution attacks.
"""

import pickle
import io

# Whitelist of allowed modules and classes for deserialization
SAFE_MODULES = {
    'builtins': {'dict', 'list', 'set', 'frozenset', 'tuple', 'str', 'int', 'float', 'bool', 'bytes', 'type', 'NoneType'},
    'datetime': {'datetime', 'date', 'time', 'timedelta', 'timezone'},
    'neo4j.time': {'DateTime', 'Date', 'Time', 'Duration'},
    'neo4j.graph': {'Node', 'Relationship', 'Path'},
    'collections': {'OrderedDict', 'defaultdict'},
    # AD_Miner internal data classes (safe - no dangerous methods)
    'ad_miner.sources.modules.path_neo4j': {'Path'},
    'ad_miner.sources.modules.node_neo4j': {'Node'},
}


class RestrictedUnpickler(pickle.Unpickler):
    """
    A restricted unpickler that only allows deserialization of whitelisted classes.

    This prevents arbitrary code execution through malicious pickle files by
    raising an error when an unauthorized class is encountered.
    """

    def find_class(self, module, name):
        if module in SAFE_MODULES and name in SAFE_MODULES[module]:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Unauthorized class: {module}.{name}. "
            "Only whitelisted classes can be deserialized for security reasons."
        )


def safe_load(file):
    """
    Safely load a pickle file using the RestrictedUnpickler.

    Args:
        file: A file-like object opened in binary mode.

    Returns:
        The deserialized Python object.

    Raises:
        pickle.UnpicklingError: If an unauthorized class is encountered.
    """
    return RestrictedUnpickler(file).load()


def safe_loads(data):
    """
    Safely load pickle data from bytes using the RestrictedUnpickler.

    Args:
        data: Bytes containing pickled data.

    Returns:
        The deserialized Python object.

    Raises:
        pickle.UnpicklingError: If an unauthorized class is encountered.
    """
    return RestrictedUnpickler(io.BytesIO(data)).load()
