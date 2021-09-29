#!/usr/bin/env python3

import os.path
import shutil
import sys

from subprocess import call
from distutils.dir_util import copy_tree


def pretty_print(message):
    print ('=== ' + message + ' ===')


pretty_print('Starting to copy mercurial to git')
pretty_print('Cloning eidas-middleware from git to /tmp/eidas-middleware')

git_local_path = "/tmp/eidas-middleware"
github_url = "git@github.com:Governikus/eidas-middleware.git"
hg_tmp_path = "/tmp/eumw"

if os.path.exists(git_local_path):
    pretty_print(git_local_path + ' does already exist')
    pretty_print('To delete the directory, type y. Otherwise this script will abort')
    answer = input("DELETE " + git_local_path + " (y|n)\n")
    if answer == 'y':
        shutil.rmtree(git_local_path)
    else:
        pretty_print('Aborting')
        sys.exit()

call(["git", "clone", github_url, git_local_path])
os.chdir(git_local_path)

pretty_print('Select the github branch for the github commit')
github_branch = input("github branch:\n")

pretty_print('Specify if a new branch needs to be created for the github commit')
github_new_branch = input("Will the commit be made on a new branch? (y/n):\n")

if github_new_branch == 'y':
    pretty_print('Specify the github tag that should be used to create the new branch on')
    github_tag_for_new_branch = input("The github tag the new branch should be created on:\n")
    call(["git", "checkout", github_tag_for_new_branch])
    call(["git", "checkout", "-b", github_branch])
else:
    call(["git", "checkout", github_branch])

os.chdir("/tmp")

if os.path.exists(hg_tmp_path):
    pretty_print(hg_tmp_path + ' does already exist')
    pretty_print('To delete the directory, type y. Otherwise this script will abort')
    answer = input("DELETE " + hg_tmp_path + " (y|n)\n")
    if answer == 'y':
        shutil.rmtree(hg_tmp_path)
    else:
        pretty_print('Aborting')
        sys.exit()

call(["hg", "clone", "https://hg.govkg.de/Autent/eumw", hg_tmp_path])

tag = input("Specify the hg tag name of the release\n")

pretty_print("Updating to " + tag + " , all non versioned files will be removed")
os.chdir(hg_tmp_path)
call(["hg", "update", "-r", tag, "-C"])
call(["hg", "purge", "--all"])
shutil.rmtree(".hg")

pretty_print("Copying cleaned eumw directory into the git directory")
os.chdir("/tmp")
shutil.copytree(git_local_path + "/.git", "/tmp/.git")
shutil.rmtree(git_local_path)
shutil.copytree("/tmp/.git", git_local_path + "/.git")
shutil.rmtree("/tmp/.git")

copy_tree(hg_tmp_path, git_local_path)

pretty_print("Creating single commit in git and push this to github")
os.chdir(git_local_path)
call(["git", "add", "-A"])
call(["git", "commit", "-m Release " + tag])
#call(["git", "push"])
pretty_print("Finished")
