
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

import logging
from datetime import datetime

LOG_LEVEL = {
    "error": logging.error,
    "info": logging.info,
    "debug": logging.debug,
    "crit": logging.critical,
    "warn": logging.warning
}


def sabo_log_init(log_path):
    logging.basicConfig(
        filename = log_path,
        format = '%(asctime)s %(process)d [%(levelname)s] %(message)s',
        datefmt = '%a, %d %b %Y %H:%M:%S',
        filemode = 'a'
    )


def sabo_error_log(level, info):
    if level not in LOG_LEVEL:
        return

    LOG_LEVEL[level](info)
