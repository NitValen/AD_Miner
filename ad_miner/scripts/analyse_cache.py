import os
import sys
from pathlib import Path

from ad_miner.sources.modules.safe_pickle import safe_load

# Constants
MODULES_DIRECTORY = Path(__file__).parent / 'sources/modules'


def request_a():
    module_name = sys.argv[1]

    # Security: Validate that module_name is a simple filename without path components
    if os.path.sep in module_name or '/' in module_name or module_name.startswith('.'):
        raise ValueError(f"Invalid module name: path components not allowed")

    return retrieveCacheEntry(module_name=module_name)


def retrieveCacheEntry(module_name: str):
    # Resolve the full path
    full_path = (MODULES_DIRECTORY / module_name).resolve()

    # Security: Verify the path stays within the allowed directory
    modules_dir_resolved = MODULES_DIRECTORY.resolve()
    if not str(full_path).startswith(str(modules_dir_resolved)):
        raise ValueError("Path traversal detected: access denied")

    with open(full_path, "rb") as f:
        return safe_load(f)


list_path = request_a()

dico_node_rel_node = {}

liste_totale = []

for path in list_path:

    for i in path.nodes:
        liste_totale += [(i.id, i.labels, i.name, i.relation_type)]

print(liste_totale, len(liste_totale))
