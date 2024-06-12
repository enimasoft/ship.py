![shippy_lbw](https://github.com/enimasoft/ship.py/assets/170250886/a69392a5-1a84-4205-84c1-0d0df36b719b)

# ship.py

This script allows you to copy files from local directory to remote directory.

### Dependencies:
The next external modules are required to use this script:
- `yaml` - to be able to parse the config file;
- `paramiko` - to be able to establish an SFTP connection;
- `requests` - in case you want to authenticate using the Vault.

If you don't already have these modules installed, the script will throw an exception with an appropriate message (e.g. "You need to install the X library").

### Usage:

`ship.py` - runs the script, which reads the `ship_config.yaml`. No profile specified, so defaults to the `default` profile.

`ship.py --profile=backup` - runs the script using the profile `backup` from the `ship_config.yaml` file.

### Features:

- Various authentication methods: password, private key (RSA, DSA, ECDSA, Ed25519), vault;
- Choose which subdirectories to exclude;
- Choose which files to ignore based on their extension;
- Backup profile: copy from local drive to external drive.
