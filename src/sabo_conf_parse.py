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

import yaml
import os


sabo_db = ["mysql"]

base_default_list = {
    "java_path"           : None,
    "log_path"            : "/var/log/",
    "work_path"           : "/tmp/",

    "daemon"              : True,
    "str_filter"          : False,

    "cocurrent"           : os.cpu_count(),
    "maxtime"             : 60 * 1000,
    "mintime"             : 1000,
    "minmem"              : 1000,
    "maxmem"              : 65536 * 4,
    "java_bonus_time"     : 1000,
    "java_bonus_mem"      : 65536,

    "filter_key_words"    : None,
    "data_path"           : None,
}

db_default_list = {
    "db_type"     : None,
    "db_user"     : None,
    "db_passwd"   : None,
    "db_name"     : None,

    "db_retry"    : 3,
    "db_interval" : 5,
    "db_port"     : 3306,
    "db_addr"     : "127.0.0.1",
}

base_check_list = {
    "java_path"        : str,
    "log_path"         : str,
    "work_path"        : str,
    "data_path"        : str,

    "daemon"           : bool,
    "str_filter"       : bool,

    "cocurrent"        : int,
    "maxtime"          : int,
    "mintime"          : int,
    "minmem"           : int,
    "maxmem"           : int,
    "java_bonus_time"  : int,
    "java_bonus_mem"   : int,

    "filter_key_words" : list,
}

db_check_list = {
    "db_type"     : str,
    "db_user"     : str,
    "db_passwd"   : str,
    "db_addr"     : str,
    "db_name"     : str,

    "db_port"     : int,
    "db_retry"    : int,
    "db_interval" : int,
}


def sabo_check_dict_item(conf, check_list, default_list):
    for item in check_list:
        if item not in conf:
            conf[item] = default_list[item]
        if not isinstance(conf[item], check_list[item]):
            return "unexpected type {0} of item {1}".format(type(conf[item]),item)


def sabo_check_filter_key_words(key_list):
    if not key_list:
        return

    for item in key_list:
        if not isinstance(item, str):
            return "unexpected type {0} of item {1}".format(type(item), item)


def sabo_check_item(conf):
    base_conf = conf.get("base", {})
    if not isinstance(base_conf, dict):
        return "unexpected type {0} of item '{1}'".format(type(base_conf), "base")

    errinfo = sabo_check_dict_item(base_conf, base_check_list, base_default_list)
    if errinfo:
        return errinfo

    db_conf = conf.get("db", {})
    if not isinstance(base_conf, dict):
        return "unexpected type {0} of item '{1}'".format(type(db_conf), "db")

    errinfo = sabo_check_dict_item(db_conf, db_check_list, db_default_list)
    if errinfo:
        return errinfo

    if conf["base"]["str_filter"]:
        errinfo = sabo_check_filter_key_words(conf["base"]["filter_key_words"])
        if errinfo:
            return errinfo

    # others check
    if db_conf["db_type"].lower() not in sabo_db:
        errinfo = "unexpected db type: {0}".format(db_conf["db_type"])

    for item in ["log_path", "work_path"]:
        if not os.path.isdir(base_conf[item]):
            try:
                os.mkdir(base_conf[item])
            except Exception as e:
                return "Create directory {0} failed: {1}".format(base_conf[item], e)

        if base_conf[item][-1:] != "/":
            base_conf[item] += "/"

        if item == "log_path":
            base_conf[item] += "sabo.log"

    if "java_path" in base_conf and not os.path.isfile(base_conf["java_path"]):
        return "{0}: No java bin".format(base_conf["java_path"])

    if "data_path" in base_conf and not os.path.isdir(base_conf["data_path"]):
        return "{0}: No such directory".format(base_conf["data_path"])

    conf["base"] = base_conf
    conf["db"] = db_conf


def sabo_yaml_parse(conf_path):
    with open(conf_path) as f:
        if not f:
            return None, "open {0} failed".format(conf_path)

        conf = yaml.load(f.read())
        if not conf:
            return None, "parse file {0} failed".format(conf_path)

    errinfo = sabo_check_item(conf)
    if errinfo:
        return None, errinfo

    return conf, None
