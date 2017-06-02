#!/usr/bin/python

delimiter = '|' # Choose the delimiter in the cache file, if you have a pipe symbol in file names you should change this

import os
import hashlib
import argparse
import time
try:
    import requests
except:
    print("This script is dependent on the requests library\nTo install it in a python3 virtualenv run:\npython3 -m venv venv\nsource venv/bin/activate\npip install requests")
    exit(1)
import re
import sys
# Using md5 as it's an inbuilt hashlib function, there's better algorithms for speed with low collisions,
# however they're not easily cross platform compatible.

deleted_files = []
new_files = []
changed_files = []
vt_results = []

def check_files(cache_file, path_to_files, vt_key):
    # This is our main function for checking the hash sums of the files
    hash_cache = {}
    try:
        open_cache_file = open(cache_file, 'r') # Loads the current cache file into a dictionary
        for line in open_cache_file:
            cache_line = line.rstrip('\n')
            fpath, hashsum = cache_line.split(delimiter)
            hash_cache[fpath] = hashsum
        open_cache_file.close()
    except IOError:
        print('Error: Could not read cache file!')
        exit(1)
    current_hashes = get_hashes(path_to_files)
    for fpath in hash_cache: # Checking if any existing files have been deleted or if their hashes have changed
        if fpath not in current_hashes:
            deleted_files.append(fpath)
        elif hash_cache[fpath] != current_hashes[fpath]:
            changed_files.append(fpath)
    for fpath in current_hashes: # Checks if the current hashes don't exist in the cache e.g new files
        if fpath not in hash_cache:
            new_files.append(fpath)
    if vt_key != False:
        for fpath in changed_files:
            check_virustotal(hash_cache[fpath], fpath, vt_key)
        for fpath in new_files:
            check_virustotal(current_hashes[fpath], fpath, vt_key)

def update_hashes(cache_file, path_to_files):
    # This function updates or creates the cache file if running for the first time
    file_hashes = get_hashes(path_to_files)
    # Now we've got a nice dictionary of the files and their hashes we need to write them to the cache file
    try:
        open_cache_file = open(cache_file, 'w')
        for fname in file_hashes:
            open_cache_file.write(fname+delimiter+file_hashes[fname]+'\n')
        open_cache_file.close()
    except IOError:
        print('Error: Could not write to cache file!')
        exit(1)

def get_hashes(path_to_files):
    file_hashes = {}
    whitelist = load_whitelist()
    if len(whitelist) == 0:
        whitelist = False
    for root, directories, filenames in os.walk(path_to_files):
        for filename in filenames:
            file_path = os.path.join(root,filename)
            if whitelist == False:
                file_hashes[file_path] = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
            else:
                whitelist_filepath = False
                for w_path in whitelist:
                    if w_path in file_path:
                        whitelist_filepath = True
                if whitelist_filepath == False:
                    file_hashes[file_path] = hashlib.md5(open(file_path, 'rb').read()).hexdigest() # Stores the file path and hash sum in a dictionary for writing to file
    return(file_hashes)

def load_whitelist(): # The whitelist file should be full paths to the files to ignore on seperate lines
    whitelist = []
    if use_whitelist == False:
        return(whitelist)
    try:
        open_whitelist_file = open(whitelist_file, 'r') # Loads the whitelist into a tuple
        for line in open_whitelist_file:
            if not line.startswith('#'):
                whitelist.append(line.rstrip('\n'))
        open_whitelist_file.close()
    except IOError:
        print('Error: Could not read whitelist file!')
        exit(1)
    return(whitelist)

def check_virustotal(filehash, fpath, vt_key):
    # This submits the file hash to VT to see if it's been previously flagged as malicious, it doesn't submit new files to VT.
    endpoint = 'https://www.virustotal.com/vtapi/v2/file/report'
    r = requests.post(endpoint, {'resource': filehash, 'apikey': vt_key})
    if r.status_code == 403:
        print('Error: Invalid VirusTotal API Key!')
        exit(1)
    elif r.status_code == 200:
        json_data = r.json()
        if json_data['response_code'] == 1 and json_data['positives'] > 0: # We should only flag if VT finds more than 1 positive scan result
            vt_results.append(fpath+', VirusTotal Result: '+json_data['permalink'])
        time.sleep(15) # VirusTotal only allows 4 requests per minute
    else:
        print('Error: An unknown response was received from VirusTotal!')
        exit(1)

def check_path(path_to_files):
    if os.path.isdir(path_to_files):
        return(True)
    else:
        return(False)

def find_wordpress_version(files):
    def pull_version(version_file):
        with open(os.path.join(version_file), 'r') as version_file:
            for line in version_file:
                if "$wp_version" in line:
                    try:
                        version = re.match(r"""\$wp_version = '(.*)'.*""", line).group(1)
                    except:
                        continue
                    return version
            return ''

    try:
        version = pull_version(os.path.join(files, "wp-includes/version.php"))
    except IOError:
        print("Locating wordpress version file")
        result = []
        for root, dirs, files in os.walk(files):
            if "version.php" in files:
                result.append(os.path.join(root, "version.php"))

        if len(result) > 1:
            for file_name in result:
                if not "wp-includes/version.php" in file_name:
                    result.remove(file_name)

        if len(result) != 1:
            if len(result) == 0:
                print("No WordPress version file found")
                return ''
            else:
                show_files = raw_input("Multiple version files found show files? [y/N]: ")
                if show_files != "y" and show_files != "Y":
                    return ''

                for file_path in result:
                    print(file_path)

                version_file = raw_input("Which is the correct file? (Leave blank to skip finding WordPress version)\n")
                if not version_file in result:
                    return ''

        if len(result) == 1:
            version_file = result[0]

        try:
            version = pull_version(version_file)
        except IOError:
            print("Error opening wordpress version file")

    return version

def get_wordpress_version_changelog(version):
    if not version:
        print("No version given")
        return ''
    try:
        response = requests.get("https://codex.wordpress.org/Version_{}".format(version))
    except requests.exceptions.ConnectionError:
        urn("Connection Error")
    if response.status_code != 200:
        print("{} Error from server".format(response.status_code))
        return ''
    if sys.version_info[0] == 3:
        try:
            return re.match(r""".*class="mw-headline" id="List_of_Files_Revised">List of Files Revised</span></h2>\\n<pre>\\n(.*)\\n</pre>.*""", str(response._content)).group(1).replace(r"\n", "\n")
        except:
            # WordPress versions before 2.0.4 didn't have a a changelog in this format, I'm sure this will catch other errors
            print("Couldn't interperate response from server")
            return ''
    try:
        return re.match(r""".*class="mw-headline" id="List_of_Files_Revised">List of Files Revised</span></h2>\\n<pre>\\n(.*)\\n</pre>.*""", repr(str(response._content))).group(1).replace(r"\n", "\n")
    except:
        # WordPress versions before 2.0.4 didn't have a a changelog in this format, I'm sure this will catch other errors
        print("Couldn't interperate response from server")
        return ''


def report_results():
    if new_files:
        print('The following new files were created:')
        for fpath in new_files:
            print(fpath)
        print('-------------------------------------')
    if changed_files:
        print('The following files were modified:')
        for fpath in changed_files:
            print(fpath)
        print('----------------------------------')
    if deleted_files:
        print('The following files were removed:')
        for fpath in deleted_files:
            print(fpath)
        print('---------------------------------')
    if vt_results:
        print('The following files were flagged by VirusTotal:')
        for fpath in vt_results:
            print(fpath)
        print('---------------------------------')

if __name__ == '__main__':
    # This allows people to either run the script from the command line or import the check_files/update_files function seperately.
    parser = argparse.ArgumentParser()
    parser.add_argument('-ca', '--cache', required=True, help='the full path to the cache file')
    parser.add_argument('-f', '--files', required=True, help='the full path to the files to check')
    parser.add_argument('-t', '--task', required=True, choices=['update','check'], help='specify task to perform')
    parser.add_argument('-w', '--whitelist', help='the full path to whitelist file')
    parser.add_argument('-vt', '--virustotal', help='specify your VirusTotal API key for checking if modified files have been flagged by VT, (warning: this is slow due to API req limits)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Checks for wordpress updates and sorts the output, only valid with --task update')
    args = parser.parse_args()
    if not args.whitelist:
        use_whitelist = False
    elif args.whitelist:
        use_whitelist = True
        whitelist_file = args.whitelist
    cache_file = args.cache
    if check_path(args.files):
        path_to_files = args.files
    else:
        print('Invalid directory path specified!')
        exit(1)
    if args.task == 'check':
        # Check VirusTotal
        if args.virustotal:
            vt_key = args.virustotal
        else:
            vt_key = False
        check_files(cache_file, path_to_files, vt_key)
        report_results()
        if args.interactive:
            # This might not be the correct way to do this
            if sys.version_info[0] == 3:
                raw_input = input
            if changed_files or new_files:
                check_update = raw_input("Check if this was a WordPress update? [y/N]: ")
                if check_update == "y" or check_update == "Y":
                    wp_version = find_wordpress_version(path_to_files)
                    if wp_version:
                        print("Detected WordPress version as {}".format(wp_version))
                        wp_updated_files = get_wordpress_version_changelog(wp_version)
                        if wp_updated_files:
                            print("The following files should have changed:\n{}".format(wp_updated_files))

    elif args.task == 'update':
        update_hashes(cache_file, path_to_files)
        print('Hashes Updated')
