# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Authoritative journal microseconds using the selected Python datetime profile.

Keep raw microseconds separate: datetime rounds its input and may reject the
calendar range even when the rational seconds value is finite.
"""
from datetime import datetime
import struct

try:
    LOCAL_TIMEZONE = datetime.now().astimezone().tzinfo
except TypeError:
    LOCAL_TIMEZONE = None


def convert(timestamp_us):
    if not isinstance(timestamp_us, str) or not timestamp_us or len(timestamp_us) > 20 or any(c not in '0123456789' for c in timestamp_us):
        raise ValueError('invalid journal microseconds')
    value = int(timestamp_us)
    if value > 18446744073709551615:
        raise ValueError('journal microseconds outside u64')
    # Integer true division matches python-systemd's timestamp converter. Casting
    # the integer to float before dividing can double-round values beyond 2^53.
    date = datetime.fromtimestamp(value / 1000000, LOCAL_TIMEZONE)
    return {'timestamp_us': timestamp_us, 'timestamp_bits': struct.pack('>d', date.timestamp()).hex(),
            'iso8601': date.isoformat(), 'time_text': date.isoformat() + ' '}
