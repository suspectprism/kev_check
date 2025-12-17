# Load the YAML configuration file into a dictionary
#
#
# P Dowley   v0.1      5 Dec 2025

import yaml

def load_config(config_file_path):
    """Load a YAML config file and return its contents as a dictionary"""

    try:
        with open(config_file_path, "r") as stream:
            # Using yaml.safe_load() for opening files to avoid arbitrary code execution
            config = yaml.safe_load(stream)
        return config
    except FileNotFoundError:
        print(f"Error: Config file '{config_file_path}' not found.")
        return None
    except yaml.YAMLError as exc:
        print(f"Error parsing YAML file: {exc}")
        return None
