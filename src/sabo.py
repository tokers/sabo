# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ACMICPC problem online judger Sabo
# Copyright (C) 2016  zchao1995@gmail.com(Zhang Chao)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.  * * You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import re
import sys
import time
import config
import multiprocessing

from os import getpid
from os import path
from os import makedirs
from os import environ
from os import fork
from os import dup2
from os import chdir
from os import setsid
from os import umask
from os import devnull
from os import listdir
from shutil import rmtree

from sabo_log import sabo_log_init, sabo_error_log
from sabo_conf_parse import sabo_yaml_parse
from sabo_database import sabo_traversal_database
from sabo_judge import sabo_workers_do


def sabo_daemon(work_path):
    try:
        child = fork()
        if child:
            sys.exit()

        chdir(work_path)
        setsid()
        umask(0)

        sys.stdout.flush()
        sys.stderr.flush()

        si = open(devnull, "r")
        so = open(devnull, "a+")
        se = open(devnull, "a+")

        dup2(si.fileno(), sys.stdin.fileno())
        dup2(so.fileno(), sys.stdout.fileno())
        dup2(se.fileno(), sys.stderr.fileno())

    except Exception as e:
        sabo_error_log("error", "fork failed: {0}".format(e))
        print("fork failed: {0}".format(e))
        sys.exit()


def sabo_init(conf):
    sabo_log_init(conf["base"]["log_path"])
    sabo_error_log("info", "sabo start...")
    task_queue = multiprocessing.JoinableQueue()
    result_queue = multiprocessing.JoinableQueue()

    return task_queue, result_queue


def sabo_run(conf_path):
    conf, err = sabo_yaml_parse(conf_path)
    if err:
        print(err)
        sys.exit()

    # remove dirs (last run)
    pattern = r"^sabo.\d+$"
    rexp = re.compile(pattern)
    for element in listdir(conf["base"]["work_path"]):
        if rexp.match(element):
            rmtree(path.join(conf["base"]["work_path"], element))

    if conf["base"]["daemon"]:
        sabo_daemon(conf["base"]["work_path"])

    task_queue, result_queue = sabo_init(conf)
    cocurrent = conf["base"]["cocurrent"]
    for i in range(cocurrent):
        sabo_worker = multiprocessing.Process(target=sabo_workers_do,
                args=(conf, task_queue, result_queue))
        sabo_worker.start()

    # sabo master for traverse the database
    sabo_traversal_database(task_queue, conf["db"])


if __name__ == '__main__':
    argv = sys.argv
    if len(argv) != 2:
        print("Usage: python3 sabo.py <conf_path>")
        sys.exit()

    conf_path = argv[1]
    sabo_run(conf_path)
