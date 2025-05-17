# chaudit-UnattendedUpdatesChecker
A simple script to check if unattended upgrades are enabled and configured correctly on Linux systems, reporting on the status and any misconfigurations. Uses apt and dpkg libraries. - Focused on Audits configuration files (YAML, JSON) against predefined security best practices and benchmarks.  Checks for weak passwords, insecure permissions, and other common misconfigurations. Can be extended with custom rule sets.

## Install
`git clone https://github.com/ShadowStrikeHQ/chaudit-unattendedupdateschecker`

## Usage
`./chaudit-unattendedupdateschecker [params]`

## Parameters
- `-h`: Show help message and exit
- `--check-upgrades`: Check unattended upgrades status.
- `--config-file`: No description provided
- `--schema-file`: Path to the JSON schema file.

## License
Copyright (c) ShadowStrikeHQ
