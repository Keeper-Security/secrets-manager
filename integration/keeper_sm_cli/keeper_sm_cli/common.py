# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#


import prettytable


def table_setup(table):
    table.align = 'l'
    table.horizontal_char = "-"
    table.vertical_char = " "
    table.junction_char = " "
    table.hrules = prettytable.HEADER
    table.left_padding_width = 0
    table.right_padding_width = 0
