#!/usr/bin/python3
# /// script
# dependencies = []
# ///

import os

# Get project root folder
project_root = os.path.dirname(os.path.realpath(__file__))
# cd into 'project root / polka'
os.chdir(project_root + "/polka")
# make
make_code = os.system("make")
# cd back
os.chdir(project_root)

if make_code == 0:
    print("Build successful.")
else:
    print("Build failed.")
