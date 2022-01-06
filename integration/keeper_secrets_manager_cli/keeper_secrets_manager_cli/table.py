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

from colorama import Style
from enum import Enum
import textwrap
import platform
import os


class ColumnAlign(Enum):
    LEFT = 'l'
    CENTER = 'c'
    RIGHT = 'r'


class Table:

    def __init__(self, use_color=True):
        self.use_color = use_color
        self.columns = []
        self.data = []
        self.spacer = " "
        self.line = "-"
        self.indent = " "

        self.max_width, _ = self._terminal_width()

    def add_column(self, title, allow_wrap=None,
                   data_color=Style.RESET_ALL, title_color=Style.RESET_ALL,
                   title_align=ColumnAlign.LEFT, data_align=ColumnAlign.LEFT, align=None):

        if align is not None:
            title_align = align
            data_align = align

        index = len(self.columns)
        self.columns.append({
            "index": index,
            "title": title,
            "title_color": title_color,
            "data_color": data_color,
            "title_align": title_align,
            "data_align": data_align,
            "width": len(title),
            "allow_wrap": allow_wrap,
            "wrap": False
        })

    def add_row(self, data):
        self.data.append(data)

    @staticmethod
    def _terminal_width():

        w = 80
        h = 25

        # We might be in an environment where is no terminal. (ie testing)
        try:
            if platform.system() == "Windows":
                w = os.get_terminal_size().columns
                h = os.get_terminal_size().lines
            else:
                import fcntl
                import termios
                import struct
                h, w, hp, wp = struct.unpack('HHHH',
                                             fcntl.ioctl(0, termios.TIOCGWINSZ,
                                                         struct.pack('HHHH', 0, 0, 0, 0)))
        except OSError as _:
            pass

        # Remove 1 from with width to be safe.
        return w - 1, h

    def _set_column_width(self, index):

        """ Find the max width of title and data for a column.
        """

        column_data: dict = self.columns[index]

        max_data_size = column_data.get("width")
        for item in self.data:
            value = item[index]
            width = len(str(value))
            # If not the last column, add the width of the spacer
            if index < len(self.columns) - 1:
                width += len(self.spacer)
            if width > max_data_size:
                max_data_size = width
        column_data["width"] = max_data_size

    def _adjust_columns(self):

        last_column = self.columns[-1]

        total_width = len(self.indent)
        total_width_minus_wrap = total_width
        allow_wraps = []
        for index in range(0, len(self.columns)):
            width = self.columns[index].get("width")
            if index != last_column.get("index"):
                width += len(self.spacer)
            total_width += width
            if self.columns[index].get("allow_wrap") is True:
                allow_wraps.append(index)
            else:
                total_width_minus_wrap += width

        # Don't try to wrap anything if the terminal is way too narrow.
        sanity_abort = (total_width / 3) > self.max_width

        # Did we go over
        if sanity_abort is False and total_width > self.max_width and len(allow_wraps) > 0:
            working_width = int((self.max_width - total_width_minus_wrap) / len(allow_wraps))
            for index in allow_wraps:
                column: dict = self.columns[index]
                column["width"] = working_width

    def _str_format(self, value, width, align, add_spacer=False):

        if value is None:
            value = " "

        value = str(value)

        text_items = textwrap.wrap(value, width)

        formatted_values = []
        for item in text_items:
            if align == ColumnAlign.RIGHT:
                item = "{:>{}}".format(item, width)
            elif align == ColumnAlign.LEFT:
                item = "{:<{}}".format(item, width)
            elif align == ColumnAlign.CENTER:
                item = "{:^{}}".format(item, width)

            # Normally the last column doesn't get a spacer added to it since we are done
            if add_spacer is True:
                item += self.spacer
            # Else remove trailing spaces. Extra space may cause huge vertical space if we can't word wrap.
            else:
                item = item.rstrip()
            formatted_values.append(item)

        return formatted_values

    def _char_line(self, char, width, add_spacer=False):

        value = char*width

        if add_spacer is True:
            value += self.spacer
        return value

    def get_string(self):

        if len(self.columns) == 0:
            raise ValueError("Columns have not been setup.")

        # For each column find the longest value, including the title
        for index in range(0, len(self.columns)):
            self._set_column_width(index)

        # Adjust the column widths so we don't overflow the console
        self._adjust_columns()

        table_str = self.indent
        line_str = self.indent

        last_column = self.columns[-1]

        # Build the column titles and separator line.
        width_left = self.max_width
        for item in self.columns:
            is_last_column = last_column["index"] == item["index"]
            text_rows = self._str_format(
                value=item["title"],
                width=item["width"],
                align=item["title_align"],
                add_spacer=not is_last_column
            )
            table_str += "".join(text_rows)

            # Prevent the separator line from being too long. The text might be really long, but it might
            # be word wrapped. If the last column, just use the remaining screen width for the line length.
            width = item["width"]
            if not is_last_column:
                width_left -= (item["width"] + len(self.spacer))
            elif width > width_left:
                width = width_left

            line_str += self._char_line(
                char=self.line,
                width=width,
                add_spacer=not is_last_column
            )

        table_str += "\n" + line_str + "\n"

        for item in self.data:
            col_rows = []
            max_text_rows = 0
            for index in range(0, len(self.columns)):
                value = item[index]
                test_rows = self._str_format(
                    value=value,
                    width=self.columns[index].get("width"),
                    align=self.columns[index].get("data_align"),
                    add_spacer=last_column["index"] != index,
                )
                if len(test_rows) > max_text_rows:
                    max_text_rows = len(test_rows)
                col_rows.append(test_rows)

            # Fill in missing rows of wrapped data with spaces
            for index in range(0, len(col_rows)):
                if len(col_rows[index]) < max_text_rows:
                    for cnt in range(len(col_rows[index]), max_text_rows):
                        spaces = self._char_line(
                            char=" ",
                            width=self.columns[index].get("width"),
                            add_spacer=last_column["index"] != index
                        )
                        col_rows[index].append(spaces)

            row_str = ""
            for row_index in range(0, max_text_rows):
                row_str += self.indent
                for column in self.columns:
                    value = col_rows[column["index"]][row_index]
                    if self.use_color is True:
                        value = column["data_color"] + value + Style.RESET_ALL
                    row_str += value
                row_str += "\n"

            table_str += row_str

        return table_str
