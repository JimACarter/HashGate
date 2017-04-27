#!/usr/bin/python

delimiter = '|' # Choose the delimiter in the cache file, if you have a pipe symbol in file names you should change this

import os, hashlib, argparse, time, requests
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

def check_filetypes(new, changed):
    """Input the lists new_files and changed_files. Returns the sum of the error codes"""
    import subprocess
    errors = 0
    for files in [new_files, changed_files]:
        for fpath in files:
            # subprocess.call(["file", fpath]) returns an error code and automatically prints the response
            # There is a filemagic library that would likely be better but I did not want to introduce it as a dependancy
            errors += subprocess.call(["file", fpath])
    return(errors)

if __name__ == '__main__':
    # This allows people to either run the script from the command line or import the check_files/update_files function seperately.
    parser = argparse.ArgumentParser()
    parser.add_argument('-ca', '--cache', required=True, help='the full path to the cache file')
    parser.add_argument('-f', '--files', required=True, help='the full path to the files to check')
    parser.add_argument('-t', '--task', required=True, choices=['update','check'], help='specify task to perform')
    parser.add_argument('-w', '--whitelist', help='the full path to whitelist file')
    parser.add_argument('-vt', '--virustotal', help='specify your VirusTotal API key for checking if modified files have been flagged by VT, (warning: this is slow due to API req limits)')
    parser.add_argument('-c', '--check-filetype', action='store_true', help='check the filetype of each changed file, only valid with --task update')
    args = parser.parse_args()
    if args.check_filetype and args.task != 'check':
        print('--check-fileype can only be used with -task update')
        exit(1)
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
        if args.check_filetype:
            errors = check_filetypes(new_files, changed_files)
            if errors:
                # I can only see this error occuring if a file that was changed or added gets removed during runtime
                print('{} Error(s) whilst checking files'.format(errors))
    elif args.task == 'update':
        update_hashes(cache_file, path_to_files)
        print('Hashes Updated')
