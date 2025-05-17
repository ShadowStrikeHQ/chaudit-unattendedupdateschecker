#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import sys
import yaml
import json
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class UnattendedUpdatesChecker:
    """
    Checks if unattended upgrades are enabled and configured correctly on Linux systems.
    Also audits configuration files (YAML, JSON) against predefined security best practices.
    """

    def __init__(self):
        """Initialize the checker."""
        self.logger = logging.getLogger(__name__)

    def check_unattended_upgrades(self):
        """
        Checks the status of unattended upgrades on Debian/Ubuntu systems.
        Returns:
            tuple: (bool, str) - (enabled, status_message)
        """
        try:
            # Check if unattended-upgrades package is installed
            result = subprocess.run(['dpkg', '-s', 'unattended-upgrades'], capture_output=True, text=True)
            if result.returncode != 0:
                return False, "Unattended upgrades package is not installed."

            # Check if unattended upgrades are enabled in APT configuration
            auto_upgrades_file = '/etc/apt/apt.conf.d/50unattended-upgrades'
            if not os.path.exists(auto_upgrades_file):
                 return False, f"Configuration file not found: {auto_upgrades_file}"
            
            with open(auto_upgrades_file, 'r') as f:
                content = f.read()

            if 'Unattended-Upgrade::Allowed-Origins' not in content:
                return False, "Unattended-Upgrade::Allowed-Origins not properly configured."

            # Check if automatic updates are enabled
            auto_updates_file = '/etc/apt/apt.conf.d/20auto-upgrades'
            if not os.path.exists(auto_updates_file):
                return False, f"Configuration file not found: {auto_updates_file}"
            
            with open(auto_updates_file, 'r') as f:
                auto_updates_content = f.read()

            if 'APT::Periodic::Update-Package-Lists "1";' not in auto_updates_content or 'APT::Periodic::Unattended-Upgrade "1";' not in auto_updates_content:
                return False, "Automatic updates are not enabled in APT::Periodic."

            return True, "Unattended upgrades are enabled and properly configured."

        except FileNotFoundError as e:
            self.logger.error(f"File not found: {e}")
            return False, f"Error: File not found: {e}"
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Subprocess error: {e}")
            return False, f"Error: Subprocess error: {e}"
        except Exception as e:
            self.logger.exception(f"An unexpected error occurred: {e}")
            return False, f"Error: An unexpected error occurred: {e}"

    def audit_config_file(self, config_file, schema_file):
        """
        Audits a configuration file (YAML/JSON) against a given schema.

        Args:
            config_file (str): Path to the configuration file.
            schema_file (str): Path to the JSON schema file.

        Returns:
            bool: True if the configuration file is valid, False otherwise.
        """
        try:
            # Determine the file type based on the extension
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                with open(config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
            elif config_file.endswith('.json'):
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
            else:
                self.logger.error("Unsupported configuration file type. Only YAML and JSON are supported.")
                return False
            
            with open(schema_file, 'r') as f:
                schema_data = json.load(f)

            validate(instance=config_data, schema=schema_data)
            self.logger.info(f"Configuration file '{config_file}' is valid against the schema.")
            return True

        except FileNotFoundError as e:
            self.logger.error(f"File not found: {e}")
            return False
        except yaml.YAMLError as e:
            self.logger.error(f"YAML parsing error: {e}")
            return False
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parsing error: {e}")
            return False
        except ValidationError as e:
            self.logger.error(f"Validation error: {e}")
            self.logger.error(f"Error message: {e.message}")
            return False
        except Exception as e:
            self.logger.exception(f"An unexpected error occurred: {e}")
            return False

def setup_argparse():
    """
    Sets up the argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description='Check unattended upgrades and audit configuration files.')
    parser.add_argument('--check-upgrades', action='store_true', help='Check unattended upgrades status.')
    parser.add_argument('--config-file', type=str, help='Path to the configuration file to audit (YAML/JSON).')
    parser.add_argument('--schema-file', type=str, help='Path to the JSON schema file.')
    return parser

def main():
    """
    Main function to execute the checks and audits.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    checker = UnattendedUpdatesChecker()

    if args.check_upgrades:
        enabled, status = checker.check_unattended_upgrades()
        print(status)

    if args.config_file and args.schema_file:
        if not os.path.exists(args.config_file):
            print(f"Error: Configuration file not found: {args.config_file}")
            sys.exit(1)
        if not os.path.exists(args.schema_file):
            print(f"Error: Schema file not found: {args.schema_file}")
            sys.exit(1)
        
        if checker.audit_config_file(args.config_file, args.schema_file):
            print("Configuration file is valid.")
        else:
            print("Configuration file is invalid.")
            sys.exit(1)

if __name__ == "__main__":
    # Example usage in offensive context: Checking for potentially vulnerable configuration
    # by comparing the running configuration against a known vulnerable schema.
    main()