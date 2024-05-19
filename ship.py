# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# ship.py version 0.6b
#
# Copyright (c) 2024 Enimasoft
#
# https://www.enimasoft.com/software/shippy
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# License: MIT License (https://opensource.org/license/mit/)
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the “Software”),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Version 0.6b: 16-may-2024
# - Small refactoring: backup profile
#
# Version 0.5b: 15-may-2024
# - Added 'backup' profile handler
#
# Version 0.4b: 08-may-2024
# - Added authentication method: pk_path_env
# - Added authentication method: pk_vault
#
# Version 0.3b: 07-may-2024
# - Added argument parsing
# - Added authentication method: pk_path_dir
#
# Version 0.2b: 05-may-2024
# - Added 'directories' entry
# - Added 'exclude' option
# - Added 'ignore' option
# - Added 'recursive' option
# - Added 'overwrite' option
#
# Version 0.1b: 09-dec-2023 23:00:00
#
# Created: 07-dec-2023 00:46:39
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Important Libraries

from os           import walk, path, mkdir, remove, stat, scandir, listdir
from re           import compile, search
from sys          import argv, platform
from stat         import S_ISDIR
from shutil       import copy2
from fnmatch      import fnmatch
from argparse     import ArgumentParser
from collections  import defaultdict

import hashlib
import requests

try:
    from yaml     import safe_load
except ImportError:
    print("Error: you need to install the 'yaml' library (for the config file).\n"
          "       You can install it by running 'pip install pyyaml'.")
    exit(1)

try:
    from paramiko import SSHClient, SFTPClient, Transport, AutoAddPolicy
except ImportError:
    print("Error: you need to install the 'paramiko' library (for ssh/sftp).\n"
          "       You can install it by running 'pip install paramiko'.")
    exit(1)

# Global Variables

profile_name         = None
username             = None
server_ip            = None
server_port          = None
password             = None
pk_path_dir          = None
pk_path_env          = None
pk_type              = None
pk_vault             = None
pk_vault_address     = None
pk_vault_token       = None
pk_vault_secret_path = None

project_dir          = None
include_base_dir     = None
server_base_dir      = None

auth_method          = None

is_dirs_entry        = None # The config file has 'directories' entry
is_exclude           = None
is_ignore            = None
is_recursive         = None
is_overwrite         = None

remote_dir_list      = None
new_remote_path      = None

src_root_dir         = None
dst_root_dir         = None

ship_config_filename = 'ship_config.yaml'

# Functions

def show_about():
    print ('''
    ship.py (c) 2024 Enimasoft
    
    This script allows you to copy files from the local directory on your
    PC to the directory on your remote server.

    This script reads the 'ship_config.yaml' configuration file to decide:
    
        - Which directories to ship (sources)
        - Where to ship them (destinations)
    
    Why this script is useful?
    
    Instead of relying on 3rd party applications, such as PuTTy, WinSCP,
    or FileZilla; or command line utilities, such as ssh, scp, sftp, etc.,
    you can use this utility to automate these operations by configuring it
    once and using it without pain.''')

#
# Helper functions
#

def config_error(msg):
    print(f"Error [{ship_config_filename}]: " + msg)
    exit(1)

def is_valid_path(path):
    not_allowed_pattern = r'["*?<>|]'
    not_allowed = search(not_allowed_pattern, path)
    return not bool(not_allowed)

def is_valid_filename(filename):
    not_allowed_pattern = r'[\\/:"<>|]'
    not_allowed = search(not_allowed_pattern, filename)
    return not bool(not_allowed)

#
# Initialize global variables to the data from 'ship_config.yaml'
#

def init_config_data(profile):

    try:
        with open(ship_config_filename, 'r') as file:
            ship_config_file = safe_load(file)

        if profile not in ship_config_file:
            config_error(f"specified profile '{profile}' was not found.")

        global is_dirs_entry

        if profile == 'backup':
            global src_root_dir, dst_root_dir

            if 'src_root_dir' in ship_config_file[profile]:
                src_root_dir = ship_config_file[profile]['src_root_dir']

                if src_root_dir is None:
                    config_error("you should specify the 'src_root_dir'.")

                if platform == 'win32':
                    src_root_dir = src_root_dir.replace("\\", "/")
            else:
                config_error("missing configuration: 'src_root_dir'.")

            if 'dst_root_dir' in ship_config_file[profile]:
                dst_root_dir = ship_config_file[profile]['dst_root_dir']

                if dst_root_dir is None:
                    config_error("you should specify the 'dst_root_dir'.")

                if platform == 'win32':
                    dst_root_dir = dst_root_dir.replace("\\", "/")
            else:
                config_error("missing configuration: 'dst_root_dir'.")

            if 'directories' in ship_config_file[profile]:
                is_dirs_entry = True
            else:
                is_dirs_entry = False

            return

        global username, server_ip, server_port, password, auth_method

        global pk_path_dir, pk_path_env, pk_vault, pk_type

        global project_dir, include_base_dir, server_base_dir

        auth_method_count = 0

        if 'server_ip' in ship_config_file[profile]:
            server_ip = ship_config_file[profile]['server_ip']

            if server_ip is None:
                config_error("you should specify the 'server_ip'.")

            ipv4 = compile(r'^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b$')
            if not ipv4.match(server_ip):
                config_error("the specified 'server_ip' is incorrect.")
        else:
            config_error("missing configuration: 'server_ip'.")

        if 'server_port' in ship_config_file[profile]:
            server_port = ship_config_file[profile]['server_port']

            if server_port is None:
                config_error("you should specify the 'server_port'.")

            if server_port < 0 or server_port > 65535:
                config_error("the specified 'server_port' should be in the range from '0' to '65535'.")
        else:
            config_error("missing configuration: 'server_port'.")

        if 'username' in ship_config_file[profile]:
            username = ship_config_file[profile]['username']

            if username is None:
                config_error("you should specify the 'username'.")
        else:
            config_error("missing configuration: 'username'.")

        if 'password' in ship_config_file[profile]:
            password = ship_config_file[profile]['password']

            if password is None:
                config_error("you should specify the 'password'.")

            auth_method = "password"
            auth_method_count += 1
        else:
            password = None

        if 'pk_path_dir' in ship_config_file[profile]:
            pk_path_dir = ship_config_file[profile]['pk_path_dir']

            if pk_path_dir is None:
                config_error("you should specify the 'pk_dir_path'.")

            auth_method = "private_key_dir"
            auth_method_count += 1
        else:
            pk_path_dir = None

        if 'pk_path_env' in ship_config_file[profile]:
            pk_path_env = ship_config_file[profile]['pk_path_env']

            if pk_path_env is None:
                config_error("you should specify the 'pk_dir_env'.")

            auth_method = "private_key_env"
            auth_method_count += 1
        else:
            pk_path_env = None

        if 'pk_vault' in ship_config_file[profile]:

            global pk_vault_address, pk_vault_token, pk_vault_secret_path

            if ship_config_file[profile]['pk_vault'] is None:
                config_error("missing entries in 'pk_vault': 'address', 'token', 'secret_path'")

            pk_vault_address     = ship_config_file[profile]['pk_vault'].get('address', None)
            pk_vault_token       = ship_config_file[profile]['pk_vault'].get('token', None)
            pk_vault_secret_path = ship_config_file[profile]['pk_vault'].get('secret_path', None)

            if pk_vault_address is None:
                config_error("you should specify the 'address' in 'pk_vault'")

            if pk_vault_token is None:
                config_error("you should specify the 'token' in 'pk_vault'")

            if pk_vault_secret_path is None:
                config_error("you should specify the 'secret_path' in 'pk_vault'")

            auth_method = "private_key_vault"
            auth_method_count += 1
        else:
            pk_vault = None

        if 'pk_type' in ship_config_file[profile]:
            pk_type = ship_config_file[profile]['pk_type']

            if pk_type is None:
                config_error("you should specify the 'pk_type' - 'RSA' or 'DSS' or 'ECDSA' or 'Ed25519'")

            if auth_method == "private_key_dir" or auth_method == "private_key_env":
                if pk_type not in ['RSA', 'DSS', 'ECDSA', 'Ed25519']:
                    config_error("the 'pk_type' should be one of these: 'RSA', 'DSS', 'ECDSA', 'Ed25519'")
        else:
            pk_type = None

        if 'project_dir' in ship_config_file[profile]:
            project_dir = ship_config_file[profile]['project_dir']

            if project_dir is None:
                config_error("you should specify the 'project_dir'.")

            if platform == 'win32':
                project_dir = project_dir.replace("\\", "/")
        else:
            config_error("missing configuration: 'project_dir'.")

        if 'include_base_dir' in ship_config_file[profile]:
            include_base_dir = ship_config_file[profile]['include_base_dir']

            if include_base_dir is None:
                config_error("you should specify the 'include_base_dir'.")
        else:
            config_error("missing configuration: 'include_base_dir'.")


        if 'server_base_dir' in ship_config_file[profile]:
            server_base_dir = ship_config_file[profile]['server_base_dir']

            if server_base_dir is None:
                config_error("you should specify the 'server_base_dir'.")
        else:
            config_error("missing configuration: 'server_base_dir'.")

        if auth_method_count == 0:
            config_error("you should specify one of the auth methods:"
                "\n\t\t\t  'password', 'pk_path_dir', 'pk_path_env', 'pk_vault'.")
        elif auth_method_count > 1:
            print( f"Error: you have more than one authentication method specified in {file.name}\n"
                    "       Authentication methods: password, pk_path_dir, pk_path_env, pk_vault")

        if 'directories' in ship_config_file[profile]:
            is_dirs_entry = True
        else:
            is_dirs_entry = False

    except FileNotFoundError:
        print(f"Error: could not open the file '{file.name}'. Check if it exists.")
        exit(1)
    except IOError:
        print(f"Error: could not read the file '{file.name}'.")
        exit(1)

#
# Get files and directories from the remote server
#

def list_remote_files_and_dirs(remote_path, sftp, indent=0):
    file_list = []

    entries = sftp.listdir_attr(remote_path)

    for entry in entries:
        entry_name = entry.filename
        entry_path = f"{remote_path}/{entry_name}" if remote_path != '/' else f"/{entry_name}"
        entry_info = sftp.lstat(entry_path)
        entry_type = 'dir' if S_ISDIR(entry_info.st_mode) else 'file'

        file_list.append({
            'name':   entry_name,
            'path':   entry_path,
            'type':   entry_type,
            'indent': indent,
        })

        if entry_type == 'dir':
            file_list.extend(list_remote_files_and_dirs(entry_path, sftp, indent+1))

    return file_list

#
# Get files and directories from the local PC (project directory)
#

def list_local_files_and_dirs(local_path, indent=0):
    file_list = []

    with scandir(local_path) as entries:
        for entry in sorted(entries, key=lambda x: x.name.lower()):
            entry_name = entry.name

            if platform == 'win32':
                entry_path = path.join(local_path, entry_name).replace("\\", "/")
            else:
                entry_path = path.join(local_path, entry_name)

            entry_type = 'dir' if entry.is_dir() else 'file'

            file_list.append({
                'name':   entry_name,
                'path':   entry_path,
                'type':   entry_type,
                'indent': indent,
            })

            if entry.is_dir():
                file_list.extend(list_local_files_and_dirs(entry_path, indent+1))

    return file_list

#
# Checks whether the remote directory that corresponds to the project's base directory exists 
#

def does_remote_base_dir_exist(remote_path, sftp):
    try:
        sftp.chdir(remote_path)
        return True
    except IOError as e:
        if e.errno == 2:
            return False
        raise

#
# Check whether the shipping dir misses files that are present in the shipped dir 
#

def get_local_files_and_dirs(local_dir):
    file_list = []
    dir_list  = []

    for root, dirs, files in walk(local_dir):
        for file in files:
            file_path     = None

            if platform == 'win32':
                file_path = path.join(root, file).replace("\\", "/")
            else:
                file_path = path.join(root, file)

            if is_dirs_entry == True:
                original_path = local_dir + "/"
            else:
                if project_dir:
                    original_path = project_dir + "/"
                else:
                    original_path = src_root_dir + "/"

            file_relpath  = file_path.replace(original_path, '')

            file_list.append(file_relpath)

        for dir in dirs:
            dir_path      = None

            if platform == 'win32':
                dir_path  = path.join(root, dir).replace("\\", "/")
            else:
                dir_path  = path.join(root, dir)

            if is_dirs_entry == True:
                original_path = local_dir + "/"
            else:
                if project_dir:
                    original_path = project_dir + "/"
                else:
                    original_path = src_root_dir + "/"

            dir_relpath   = dir_path.replace(original_path, '')

            dir_list.append(dir_relpath)

    return file_list

def get_remote_files_and_dirs(remote_dir, sftp):
    file_list = []
    dir_list  = []

    for entry in sftp.listdir_attr(remote_dir):

        entry_path    = remote_dir + "/" + entry.filename

        original_path = new_remote_path + "/"

        entry_relpath = entry_path.replace(original_path, '')

        if S_ISDIR(entry.st_mode):
            dir_list.append(entry_relpath)
            file_list.extend(get_remote_files_and_dirs(entry_path, sftp))
        else:
            file_list.append(entry_relpath)

    return file_list

def get_missing_files(local_path, remote_path, sftp=None):
    # We are subtracting 'remote_files' with 'local_files', which is going
    # to find the missing files from the LOCAL directory. That means that
    # the point of this function is to find out whether the files that can
    # be found in the remote directory can also be found in the local
    # directory.

    # If there are files that are present in the remote directory, but the
    # local files that are being shipped do not contain those files, this
    # function is going to be triggered to tell which files are in the
    # remote directory but are NOT included in the current shipping batch.

    if sftp:
        local_files   = set(get_local_files_and_dirs(local_path))
        remote_files  = set(get_remote_files_and_dirs(remote_path, sftp))
    else:
        local_files   = set(get_local_files_and_dirs(local_path))
        remote_files  = set(get_local_files_and_dirs(remote_path))

    return list(remote_files - local_files)


#
# Check whether the files are identical to skip copying
#

def get_sha256_of_local_file(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, 'rb') as file:
        sha256.update(file.read())

    return sha256.hexdigest()

def get_sha256_of_remote_file(file_path, sftp):
    sha256 = hashlib.sha256()

    with sftp.file(file_path, 'rb') as remote_file:
        sha256.update(remote_file.read())

    return sha256.hexdigest()


#
# Upload directories from the client (your PC) to the remote server
#

def sftp_upload_directories(sftp, local_path, remote_path, exclude=None, ignore=None, recursive=None, overwrite=None):

    if not path.exists(local_path):
        config_error("The specified source path does not exist.")
        exit(1)

    global new_remote_path

    if include_base_dir == True:
        if platform == 'win32':
            new_remote_path = path.join(remote_path, path.basename(local_path)).replace("\\", "/")
        else:
            new_remote_path = path.join(remote_path, path.basename(local_path))
    else:
        new_remote_path = remote_path

    if is_dirs_entry == True:
        new_remote_path = remote_path

    if not does_remote_base_dir_exist(new_remote_path, sftp):
        try:
            sftp.mkdir(new_remote_path)
        except Exception as e:
            print(f"{e}: could not create a remote directory: {new_remote_path}")

    # Check whether there are files in the remote directory that are not present in
    # the local directory that is being shipped.
    missing_files = get_missing_files(local_path, new_remote_path, sftp)

    if missing_files:
        print("\nThese files have been shipped before, but were not found in the current shipping batch:\n")

        for missing_file in missing_files:
            if platform == 'win32':
                missing_file_path = path.join(new_remote_path, missing_file).replace('\\', '/')
            else:
                missing_file_path = path.join(new_remote_path, missing_file)

            print(f"- {missing_file_path}")

        print()

        while True:
            choice       = ''
            confirmation = f"Do you want to delete these files? (y/n): {choice}"
            action       = input(confirmation)

            if action == 'y':

                print("\nDeleting the files...\n")

                for missing_file in missing_files:
                    if platform == 'win32':
                        missing_file_path = path.join(new_remote_path, missing_file).replace('\\', '/')
                    else:
                        missing_file_path = path.join(new_remote_path, missing_file)

                    try:
                        sftp.remove(missing_file_path)
                        print(f"Deleted: {missing_file_path}")
                    except FileNotFoundError:
                        print(f"Error: could not find '{missing_file_path}'")
                    except Exception as e:
                        print(f"Error: could not delete '{missing_file_path}': {e}")

                break

            elif action == 'n': break

    # Start copying from local to remote

    print(f"Copying from {local_path} to {new_remote_path}...")

    if is_dirs_entry == True and is_recursive == False:
        local_files = listdir(local_path)

        for local_file in local_files:
            if platform == 'win32':
                local_file_path  = path.join(local_path, local_file).replace('\\', '/')
                remote_file_path = path.join(new_remote_path, local_file).replace('\\', '/')
            else:
                local_file_path  = path.join(local_path, local_file)
                remote_file_path = path.join(new_remote_path, local_file)

            if path.isdir(local_file_path) == False:
                if is_overwrite == False:
                    try:
                        sftp.stat(remote_file_path)
                        print(f"File '{local_file}' already exists on the remote directory. Skipping...")
                    except FileNotFoundError:
                        sftp.put(local_file_path, remote_file_path)
                else:
                    try:
                        sftp.put(local_file_path, remote_file_path)
                        print(f"Success: '{local_file_path}' > '{remote_file_path}'")
                    except Exception as e:
                        print(f"Error: could not upload the file '{local_file}': {e}")
                        exit(1)
        return

    for root, dirs, files in walk(local_path):
        for dir_name in dirs:
            if platform == 'win32':
                local_dir  = path.join(root, dir_name).replace("\\", "/")
                remote_dir = path.join(new_remote_path, path.relpath(local_dir, local_path)).replace("\\", "/")
            else:
                local_dir  = path.join(root, dir_name)
                remote_dir = path.join(new_remote_path, path.relpath(local_dir, local_path))

            if is_exclude:
                if local_dir in exclude:
                    print(f"Excluding '{local_dir}'...")
                    continue

            try:
                sftp.mkdir(remote_dir)
                print(f"Success: '{local_dir}' > '{remote_dir}'")
            except Exception as e:
                pass

        for file_name in files:
            if platform == 'win32':
                local_file  = path.join(root, file_name).replace("\\", "/")
                remote_file = path.join(new_remote_path, path.relpath(local_file, local_path)).replace("\\", "/")
            else:
                local_file  = path.join(root, file_name)
                remote_file = path.join(new_remote_path, path.relpath(local_file, local_path))

            skip_excluded_file = None

            if is_exclude:
                for entry in exclude:
                    if entry in local_file:
                        skip_excluded_file = True
                        break

            if skip_excluded_file == True:
                continue

            skip_ignored_file = None

            if is_ignore:
                for entry in ignore:
                    if fnmatch(local_file, entry):
                        skip_ignored_file = True
                        break

            if skip_ignored_file == True:
                continue

            local_file_hash = get_sha256_of_local_file(local_file)

            try:
                remote_file_hash = get_sha256_of_remote_file(remote_file, sftp)
            except FileNotFoundError:
                remote_file_hash = None

            # This part might prevent the next block of code from execution, because
            # this one checks the hashes to avoid an overwrite, meanwhile the next
            # block prevents the overwrite based on the 'overwrite' flag being false.
            if local_file_hash == remote_file_hash:
                continue

            if is_overwrite == False:
                local_filename = path.relpath(local_file, local_path)
                try:
                    sftp.stat(remote_file)
                    print(f"File '{local_filename}' already exists on the remote directory. Skipping...")
                    continue
                except FileNotFoundError:
                    pass

            try:
                sftp.put(local_file, remote_file)
                print(f"Success: '{local_file}' > '{remote_file}'")
            except Exception as e:
                print(f"Error: could not upload the file '{local_file}': {e}")
                exit(1)


#
# Use the 'backup' profile
#

def use_backup_profile(local_path, remote_path, exclude=None, ignore=None, recursive=None, overwrite=None):

    if not path.exists(local_path):
        config_error("The specified source path does not exist.")
        exit(1)

    if not path.exists(dst_root_dir):
        try:
            mkdir(dst_root_dir)
        except Exception as e:
            print(f"{e}: could not create a directory at: {dst_root_dir}")

    if not path.exists(remote_path):
        try:
            mkdir(remote_path)
        except Exception as e:
            print(f"{e}: could not create a directory at: {remote_path}")

    missing_files = get_missing_files(local_path, remote_path)

    if missing_files:
        print("\nThese files have been shipped before, but were not found in the current shipping batch:\n")

        for missing_file in missing_files:
            if platform == 'win32':
                missing_file_path = path.join(remote_path, missing_file).replace('\\', '/')
            else:
                missing_file_path = path.join(remote_path, missing_file)

            print(f"- {missing_file_path}")

        print()

        while True:
            choice       = ''
            confirmation = f"Do you want to delete these files? (y/n): {choice}"
            action       = input(confirmation)

            if action == 'y':

                print("\nDeleting the files...\n")

                for missing_file in missing_files:
                    if platform == 'win32':
                        missing_file_path = path.join(remote_path, missing_file).replace('\\', '/')
                    else:
                        missing_file_path = path.join(remote_path, missing_file)

                    try:
                        remove(missing_file_path)
                        print(f"Deleted: {missing_file_path}")
                    except FileNotFoundError:
                        print(f"Error: could not find '{missing_file_path}'")
                    except Exception as e:
                        print(f"Error: could not delete '{missing_file_path}': {e}")

                break

            elif action == 'n': break

    # Start copying from local to remote

    print(f"Copying from {local_path} to {remote_path}...")

    if is_dirs_entry == True and is_recursive == False:
        local_files = listdir(local_path)

        for local_file in local_files:
            if platform == 'win32':
                local_file_path  = path.join(local_path, local_file).replace('\\', '/')
                remote_file_path = path.join(remote_path, local_file).replace('\\', '/')
            else:
                local_file_path  = path.join(local_path, local_file)
                remote_file_path = path.join(remote_path, local_file)

            if path.isdir(local_file_path) == False:
                if is_overwrite == False:
                    try:
                        stat(remote_file_path)
                        print(f"File '{local_file}' already exists in the destination directory. Skipping...")
                    except FileNotFoundError:
                        copy2(local_file_path, remote_file_path)
                else:
                    try:
                        copy2(local_file_path, remote_file_path)
                        print(f"Success: '{local_file_path}' > '{remote_file_path}'")
                    except Exception as e:
                        print(f"Error: could not copy the file '{local_file}': {e}")
                        exit(1)
        return

    for root, dirs, files in walk(local_path):
        for dir_name in dirs:
            if platform == 'win32':
                local_dir  = path.join(root, dir_name).replace("\\", "/")
                remote_dir = path.join(remote_path, path.relpath(local_dir, local_path)).replace("\\", "/")
            else:
                local_dir  = path.join(root, dir_name)
                remote_dir = path.join(remote_path, path.relpath(local_dir, local_path))

            if is_exclude:
                if local_dir in exclude:
                    print(f"Excluding '{local_dir}'...")
                    continue

            try:
                mkdir(remote_dir)
                print(f"Success: '{local_dir}' > '{remote_dir}'")
            except Exception as e:
                pass

        for file_name in files:
            if platform == 'win32':
                local_file  = path.join(root, file_name).replace("\\", "/")
                remote_file = path.join(remote_path, path.relpath(local_file, local_path)).replace("\\", "/")
            else:
                local_file  = path.join(root, file_name)
                remote_file = path.join(remote_path, path.relpath(local_file, local_path))

            skip_excluded_file = None

            if is_exclude:
                for entry in exclude:
                    if entry in local_file:
                        skip_excluded_file = True
                        break

            if skip_excluded_file == True:
                continue

            skip_ignored_file = None

            if is_ignore:
                for entry in ignore:
                    if fnmatch(local_file, entry):
                        skip_ignored_file = True
                        break

            if skip_ignored_file == True:
                continue

            local_file_hash  = get_sha256_of_local_file(local_file)

            try:
                remote_file_hash = get_sha256_of_local_file(remote_file)
            except FileNotFoundError:
                remote_file_hash = None

            if local_file_hash == remote_file_hash:
                continue

            if is_overwrite == False:
                local_filename = path.relpath(local_file, local_path)
                try:
                    stat(remote_file)
                    print(f"File '{local_filename}' already exists in the destination directory. Skipping...")
                    continue
                except FileNotFoundError:
                    pass

            try:
                copy2(local_file, remote_file)
                print(f"Success: '{local_file}' > '{remote_file}'")
            except Exception as e:
                print(f"Error: could not copy the file '{local_file}': {e}")
                exit(1)

#
# Initialize 'directories' entry data from 'ship_config.yaml' file
#

def read_config_directories_entry(profile, sftp=None):
    try:
        with open(ship_config_filename, 'r') as file:
            ship_config_file = safe_load(file)

        directories = []

        for entry in ship_config_file.get(profile, {}).get('directories', []):
            if sftp:
                source_path = entry.get('source').replace('{project_dir}', project_dir)
                dest_path   = entry.get('destination').replace('{server_base_dir}', server_base_dir)
            else:
                source_path = entry.get('source').replace('{src_root_dir}', src_root_dir)
                dest_path   = entry.get('destination').replace('{dst_root_dir}', dst_root_dir)
                if platform == 'win32':
                    source_path = source_path.replace("/", "\\")
                    dest_path   = dest_path.replace("/", "\\")
                else:
                    source_path = source_path.replace("\\", "/")
                    dest_path   = dest_path.replace("\\", "/")
            exclude     = entry.get('exclude', [])
            ignore      = entry.get('ignore',  [])
            options     = entry.get('options', [])

            if not source_path[0].isalpha() or is_valid_path(source_path) == False:
                print(f"source_path: {source_path}")
                config_error("The 'source' entry contains an invalid path")

            if dest_path[0] != '/':
                if not dest_path[0].isalpha() or is_valid_path(dest_path) == False:
                    config_error("The 'destination' entry contains an invalid path")

            for item in range(len(exclude)):
                if sftp:
                    exclude[item] = exclude[item].replace('{project_dir}', project_dir)
                else:
                    exclude[item] = exclude[item].replace('{src_root_dir}', src_root_dir)
                exclude_item  = exclude[item]
                if not exclude_item[0].isalpha() or is_valid_path(exclude[item]) == False:
                    config_error("The 'exclude' entry contains an invalid path")

            for item in range(len(ignore)):
                ignore_item = ignore[item]
                if ignore_item[0] != '*' or ignore_item[0] != '?':
                    if is_valid_filename(ignore_item) == False:
                        config_error("The 'ignore' entry contains an invalid filename")

            if source_path:
                directories.append({'source':source_path})
            if dest_path:
                directories.append({'destination':dest_path})
            if exclude:
                directories.append({'exclude':exclude})
            if ignore:
                directories.append({'ignore':ignore})
            if options:
                directories.append({'options':options})

            recursive = options[0].get('recursive')
            overwrite = options[0].get('overwrite')

            global is_exclude, is_ignore, is_recursive, is_overwrite

            if exclude:
                is_exclude = True
            else:
                is_exclude = False

            if ignore:
                is_ignore = True
            else:
                is_ignore = False

            if recursive == True:
                is_recursive = True
            else:
                is_recursive = False

            if overwrite == True:
                is_overwrite = True
            else:
                is_overwrite = False

            if sftp:
                sftp_upload_directories(sftp, source_path, dest_path, exclude, ignore, recursive, overwrite)
            else:
                use_backup_profile(source_path, dest_path, exclude, ignore, recursive, overwrite)

    except FileNotFoundError:
        print(f"Error: could not open the file '{file.name}'. Check if it exists.")
        exit(1)
    except IOError:
        print(f"Error: could not read the file '{file.name}'.")
        exit(1)

#
# Connect to the remote server with the SFTP protocol
#

def load_private_key(path):
    print("Loading the private key...\n")

    if pk_type == "RSA":
        private_key = RSAKey.from_private_key_file(path)
    elif pk_type == "DSS":
        private_key = DSSKey.from_private_key_file(path)
    elif pk_type == "ECDSA":
        private_key = ECDSAKey.from_private_key_file(path)
    elif pk_type == "Ed25519":
        private_key = Ed25519Key.from_private_key_file(path)

    return private_key

def get_private_key_from_vault(address, token, secret_path):
    print("Retrieving the private key from vault...\n")

    headers  = { 'X-Vault-Token': token }
    url      = f"{address}/v1/{secret_path}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        secret_data = response.json()['data']
        private_key = secret_data['private_key']
        return private_key
    else:
        print(f"Failed to retrive the private key from the vault. Status code: {response.status_code}")
        exit(1)

def connect_with_sftp(profile):

    print("Establishing an SFTP connection...\n")

    try:
        transport = Transport((server_ip, server_port))

        if auth_method is None:
            config_error("Must specify the authentication method - 'password' or 'pk_path_dir' or 'pk_path_env' or 'pk_vault'.")

        elif auth_method == "password":

            transport.connect(username=username, password=password)

        elif auth_method == "private_key_dir":

            private_key = load_private_key(pk_path_dir)

            transport.connect(username=username, pkey=private_key)

        elif auth_method == "private_key_env":

            pk_path_env_var = os.environ.get(pk_path_env)

            private_key = load_private_key(pk_path_env_var)

            transport.connect(username=username, pkey=private_key)

        elif auth_method == "private_key_vault":
            
            private_key = get_private_key_from_vault(pk_vault_address, pk_vault_token, pk_vault_secret_path)

            transport.connect(username=username, pkey=private_key)

        sftp = SFTPClient.from_transport(transport)

        if is_dirs_entry == True:
            read_config_directories_entry(profile, sftp)
        else:
            sftp_upload_directories(sftp, project_dir, server_base_dir)

    except Exception as e:
        print(f"Error: {e}")

    finally:
        if 'sftp' in locals():
            sftp.close()

        if 'transport' in locals():
            transport.close()

#
# Connect to the remote server with the SSH protocol
#
# NOT USED: RESERVED FOR THE FUTURE
#

def connect_with_ssh(profile):

    print("Establishing an SSH connection...\n")

    ssh_client  = SSHClient()

    try:
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())

        ssh_client.connect(server_ip, port=server_port, username=username, password=password)

        sftp = ssh_client.open_sftp()

        # --- START ---



        # --- END ---

        sftp.close()

    except Exception as e:
        print(f"Error: {e}")

    finally:
        ssh_client.close()

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Main Function
#

def main() -> None:

    print("ship.py version 0.6b (c) 2024 Enimasoft\n")

    arg_parser = ArgumentParser(
        prog='ship.py',
        description='This script allows you to copy files from the local directory on your PC to the directory on your remote server')

    arg_parser.add_argument('--profile', type=str,
        help='Specify the profile from the \'ship_config.yaml\' file.')

    args = arg_parser.parse_args()


    profile = None

    if args.profile is None:
        profile = 'default'
    else:
        profile = args.profile

    print(f"Using profile '{profile}'\n")

    init_config_data(profile)

    if profile == 'backup':
        read_config_directories_entry(profile)
    else:
        connect_with_sftp(profile)

    print("\nDone.\n")


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# script Run
#

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Unexpected error: {e}")
        exit(1)
    else:
        exit(0)
