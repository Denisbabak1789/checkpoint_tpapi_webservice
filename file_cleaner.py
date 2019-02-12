import os
import sys
import time


number_of_days = 30
files_dirs = ('/uploads/', '/cleaned_files/')
time_in_secs = time.time() - (number_of_days * 24 * 60 * 60)

for files_dirs in files_dirs:
    path = os.getcwd()+files_dirs
    for root, dirs, files in os.walk(path, topdown=False):
        for file_ in files:
            full_path = os.path.join(root, file_)
            stat = os.stat(full_path)
            if stat.st_mtime <= time_in_secs:
                os.remove(full_path)
                print("removed "+full_path)

