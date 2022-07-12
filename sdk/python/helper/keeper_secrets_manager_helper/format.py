# -*- coding: utf-8 -*-

import iso8601
from datetime import datetime


def date_to_ms(value):

    try:
        # Check if already an integer value
        try:
            value = int(value)
        # Else try to parse the string into a date
        except ValueError as _:
            dt = iso8601.parse_date(value)
            # Set the epoch timestamp to have the same timezone as the parsed value
            epoch = datetime.utcfromtimestamp(0).replace(tzinfo=dt.tzinfo)
            value = int((dt - epoch).total_seconds() * 1000.0)
    except iso8601.iso8601.ParseError as err:
        raise ValueError("Cannot format date/time as milliseconds: {}".format(err))

    return value
