# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
"""Date parsing component; caller supplies wall time, host timezone and saved context.

Regex matching must run under the D1 supervisor's CPU/memory/deadline limits.
No Fail2Ban imports. Source-declared catalog data retains its attribution separately.
"""
import _strptime
import calendar
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import hashlib
import math
from pathlib import Path
import re
import time

PROFILE = json.loads(Path(__file__).with_name('date_profile.json').read_text())
ZONES = PROFILE['timezone_minutes']


def timezone_minutes(value):
    if value is None:
        return None
    if type(value) is int:
        return value
    if not isinstance(value, str) or len(value) > 32:
        raise ValueError('invalid fixed timezone')
    match = re.fullmatch(r'([A-Z](?:[A-Z]{2,4})?)?([+-][01]\d(?::?\d{2})?)?', value)
    if not match:
        raise ValueError('unknown fixed timezone')
    name, offset = match.groups()
    if (name or '') not in ZONES:
        raise ValueError('unknown fixed timezone abbreviation')
    result = ZONES[name or '']
    if offset:
        compact = offset[1:].replace(':', '')
        minutes = int(compact[:2]) * 60 + (int(compact[2:]) if len(compact) > 2 else 0)
        result += -minutes if offset[0] == '-' else minutes
    return result


def directives(reference_year):
    table = dict(_strptime.TimeRE())
    # Field names are transport data shared with the date normalization stage.
    patterns = {
        'd': '[1-2]\\d|[0 ]?[1-9]|3[01]', 'm': '0?[1-9]|1[0-2]',
        'Y': '\\d{4}', 'H': '[01]?\\d|2[0-3]', 'M': '[0-5]?\\d',
        'S': '[0-5]?\\d|6[01]', 'Z': 'Z|[A-Z]{3,5}',
        'z': 'Z|UTC|GMT|[+-][01]\\d(?::?\\d{2})?',
    }
    for name, expression in patterns.items():
        table[name] = f'(?P<{name}>{expression})'
    table['k'] = r' ?(?P<H>[0-2]?\d)'
    table['l'] = r' ?(?P<I>1?\d)'
    for name, expression in {'d':'[1-2]\\d|0[1-9]|3[01]', 'm':'0[1-9]|1[0-2]',
                             'H':'[01]\\d|2[0-3]', 'M':'[0-5]\\d', 'S':'[0-5]\\d|6[01]'}.items():
        table['Ex'+name] = f'(?P<{name}>{expression})'
    table['Exk'] = r' ?(?P<H>[01]?\d|2[0-3])'
    table['Exl'] = r' ?(?P<I>1[0-2]|\d)'
    table['Exy'] = r'(?P<y>\d{2})'
    decades = sorted({str(year)[:3] for year in range(2001, reference_year + 4, 3)} | {str(reference_year - 1)[:3], str(reference_year + 3)[:3]})
    table['ExY'] = '(?P<Y>(?:'+'|'.join(decades)+')\\d)'
    abbreviation = r'[A-Z](?:[A-Z]{2,4})?'
    table['ExZ'] = f'(?P<Z>{abbreviation})'
    table['Exz'] = f'(?P<z>(?:{abbreviation})?[+-][01]\\d(?::?\\d{{2}})?|{abbreviation})'
    return table


@dataclass(frozen=True)
class DateResult:
    effective: float | None
    raw_timestamp: float | None
    text: str
    start: int
    end: int
    kind: str
    diagnostic: str | None = None


class DatePattern:
    def __init__(self, pattern, *, reference_year, anchored=False):
        if not isinstance(pattern, str) or len(pattern) > 16384:
            raise ValueError('invalid date pattern')
        if not 1 <= reference_year <= 9996:
            raise ValueError('invalid profile year')
        self.pattern = pattern
        self.weight = 100.0 if anchored else 1.0
        text = pattern.strip()
        key = text.upper() if '%' not in text else text
        self.kind = 'pattern'
        if key == '{NONE}':
            text = '{UNB}^'
        epoch = 'LEPOCH' if 'LEPOCH' in key else 'EPOCH'
        if key in (epoch, '^'+epoch, '{^LN-BEG}'+epoch) or re.search(r'(?<!\\)\{L?EPOCH\}', key):
            self.kind = epoch.lower()
            body = r'\d{10,11}\b(?:\.\d{3,6})?' if epoch == 'EPOCH' else r'\d{10,11}(?:\d{3}(?:\.\d{1,6}|\d{3})?)?'
            if key in (epoch, '^'+epoch, '{^LN-BEG}'+epoch):
                self.epoch_group = 1
                if anchored or key != epoch:
                    text = r'{^LN-BEG}((?P<square>(?<=^\[))?'+body+r')(?(square)(?=\]))'
                else:
                    text = r'((?:^|(?P<square>(?<=^\[))|(?P<selinux>(?<=\baudit\()))'+body+r')(?:(?(selinux)(?=:\d+\)))|(?(square)(?=\])))'
            else:
                self.epoch_group = 2
                if not self._has_capture(text):
                    text = '('+text+')'
                text = re.sub(r'(?<!\\)\{L?EPOCH\}', lambda _: '('+body+')', text, flags=re.I)
        elif key in ('TAI64N', '^TAI64N', '{^LN-BEG}TAI64N'):
            self.kind = 'tai64n'
            text = ('{^LN-BEG}' if anchored or key != 'TAI64N' else '{UNB}') + r'@[0-9a-f]{24}'
        else:
            table = directives(reference_year)
            tokens = re.compile(r'%(Ex[a-zA-Z]|.)')
            def replace(match):
                code = match[1]
                if code not in table:
                    raise ValueError('unsupported date directive: '+code)
                return table[code]
            text = tokens.sub(replace, text)
        self.anchored = anchored or text.startswith('{^LN-BEG}')
        unbound = text.startswith('{UNB}')
        if unbound:
            text = text[5:]
        if text.startswith('{^LN-BEG}'):
            text = text[9:]
        flags = re.I if re.search(r'(?<!%)%[aAbBpc]', pattern) else 0
        for global_flag in re.findall(r'\(\?([aiLmsux]+)\)', text):
            for flag in global_flag:
                if flag == 'L':
                    raise ValueError('locale byte regex not supported for Unicode records')
                flags |= {'a':re.A,'i':re.I,'m':re.M,'s':re.S,'u':re.U,'x':re.X}[flag]
        text = re.sub(r'\(\?[aiLmsux]+\)', '', text)
        left_unbound = text.startswith('**')
        right_unbound = text.endswith('**')
        if left_unbound:
            text = text[2:]
        if right_unbound:
            text = text[:-2]
        if not self._has_capture(text):
            if text.startswith('^'):
                text = '^('+text[1:]+')'
            else:
                text = '('+text+')'
        line_anchor = bool(re.match(r'^(?:\^|\((?:\?:)?\^(?!\|))', text))
        line_end = bool(re.search(r'(?<![\\|])\$\)?$', text))
        self.anchored = self.anchored or line_anchor or line_end
        if anchored or pattern.startswith('{^LN-BEG}'):
            text = r'^(?:\W{0,2})?'+text
        elif not unbound and not left_unbound and not line_anchor and self.kind != 'epoch':
            text = r'(?=^|\b|\W)'+text
        if not unbound and not right_unbound and not line_end and not re.search(r'\\[bs]$', text):
            text += r'(?=\b|\W|$)'
        self.regex = re.compile(text, flags)

    @staticmethod
    def _has_capture(text):
        return bool(re.search(r'(?<!\\)\((?!\?)', text))

    def match(self, line, start=0, end=None):
        if not isinstance(line, str) or len(line) > 1 << 20:
            raise ValueError('date record exceeds input budget')
        return self.regex.search(line, start, len(line) if end is None else end)

    def decode(self, match, *, now, default_tz=None):
        if not math.isfinite(now):
            raise ValueError('nonfinite date context')
        text = match[1]
        if not text:
            return DateResult(None, None, text, *match.span(1), 'optional-empty')
        if self.kind in ('epoch', 'lepoch'):
            value = match[self.epoch_group]
            if self.kind == 'lepoch' and len(value) >= 13:
                value = value[:10]+'.'+value[10:] if '.' not in value and len(value) >= 16 else str(float(value)/1000)
            seconds = float(value)
            return DateResult(seconds, seconds, text, *match.span(1), self.kind)
        if self.kind == 'tai64n':
            seconds = int(text[2:17], 16)
            return DateResult(float(seconds), float(seconds), text, *match.span(1), self.kind)
        try:
            effective, raw = normalize_fields(match.groupdict(), now=now, default_tz=default_tz)
            return DateResult(effective, raw, text, *match.span(1), 'pattern')
        except (ValueError, KeyError, OverflowError):
            return DateResult(None, None, text, *match.span(1), 'invalid', 'invalid-calendar-time')


def normalize_fields(fields, *, now, default_tz=None):
    fields = {name:value for name,value in fields.items() if value is not None}
    local_now = datetime.fromtimestamp(now)
    locale = _strptime.LocaleTime()
    year = int(fields['Y']) if 'Y' in fields else int(fields['y'])+2000 if 'y' in fields else local_now.year
    month = int(fields['m']) if 'm' in fields else locale.f_month.index(fields['B'].lower()) if 'B' in fields else locale.a_month.index(fields['b'].lower()) if 'b' in fields else None
    day = int(fields['d']) if 'd' in fields else None
    weekday = locale.f_weekday.index(fields['A'].lower()) if 'A' in fields else locale.a_weekday.index(fields['a'].lower()) if 'a' in fields else (int(fields['w'])+6)%7 if 'w' in fields else None
    julian = int(fields['j']) if 'j' in fields else None
    if julian is None and weekday is not None and ('U' in fields or 'W' in fields):
        week_type = 'U' if 'U' in fields else 'W'
        julian = _strptime._calc_julian_from_U_or_W(year, int(fields[week_type]), weekday, week_type == 'W')
    if julian is not None:
        from_ordinal = datetime.fromordinal(datetime(year, 1, 1).toordinal()+julian-1)
        year, month, day = from_ordinal.year, from_ordinal.month, from_ordinal.day
    today = month is None and day is None
    if today:
        month, day = local_now.month, local_now.day
    hour = int(fields.get('H', fields.get('I', 0)))
    if 'I' in fields:
        is_pm = fields.get('p', '').lower() == locale.am_pm[1]
        hour = hour % 12 + (12 if is_pm else 0)
    value = datetime(year, month, day, hour, int(fields.get('M',0)), int(fields.get('S',0)))
    zone = timezone_minutes(fields.get('z', fields.get('Z', default_tz)))
    if zone is not None:
        value -= timedelta(minutes=zone)
    if today and value > local_now:
        value -= timedelta(days=1)
    if 'Y' not in fields and 'y' not in fields and value > local_now + timedelta(days=1):
        value = value.replace(year=year-1, month=month, day=day)
    seconds = float(calendar.timegm(value.utctimetuple()) if zone is not None else time.mktime(value.timetuple()))
    try:
        fraction = float('0.'+fields['f']) if fields.get('f') else 0.0
    except ValueError:
        # Custom named f groups need not be numeric; the pinned effective
        # calendar parser ignores f. Preserve its result and raw text.
        return seconds, None
    return seconds, seconds + fraction if math.isfinite(fraction) else None


class DateDetector:
    """Configured templates with explicit serializable matching-history state.

    The context is independent of filters' last-date state. Clock values are passed in,
    including the real usage clock used for template aging by the reference.
    """
    def __init__(self, patterns=None, *, reference_year, default_tz=None):
        self.default_tz = timezone_minutes(default_tz)
        self.templates = []
        self._keys = set()
        if patterns is None or patterns == []:
            patterns = ['{DEFAULT}']
        if not isinstance(patterns, list) or len(patterns) > 256:
            raise ValueError('invalid pattern collection')
        for pattern in patterns:
            if pattern in ('{DEFAULT}', '{^LN-BEG}'):
                definitions = PROFILE['default_patterns']
                for definition in definitions:
                    if not definition.startswith(('^', '{^LN-BEG}')):
                        self._add(definition, reference_year, True, True)
                for definition in definitions:
                    if pattern == '{DEFAULT}' or definition.startswith(('^', '{^LN-BEG}')):
                        self._add(definition, reference_year, False, True)
            elif re.search(r'(?<!\\)\{DATE\}', pattern, re.I):
                for definition in PROFILE['default_patterns']:
                    if definition in ('EPOCH','LEPOCH'):
                        definition = '{'+definition+'}'
                    definition = definition.removeprefix('{^LN-BEG}')
                    self._add(re.sub(r'(?<!\\)\{DATE\}', lambda _:definition, pattern, flags=re.I), reference_year, False, True)
            else:
                self._add(pattern, reference_year, False, False)
        if len(self.templates) > 256:
            raise ValueError('expanded template budget exceeded')
        self.identity = hashlib.sha256(json.dumps([patterns,reference_year,self.default_tz],ensure_ascii=True,separators=(',',':')).encode()).hexdigest()

    def _add(self, pattern, year, anchored, ignore_duplicate):
        key = (pattern, anchored)
        if key in self._keys:
            if ignore_duplicate:
                return
            raise ValueError('duplicate date pattern')
        self._keys.add(key)
        self.templates.append(DatePattern(pattern, reference_year=year, anchored=anchored))

    def empty_context(self):
        count = len(self.templates)
        return dict(version=1, identity=self.identity, order=list(range(count)),
                    stats=[dict(hits=0, match_hits=0, used=0.0, distance=2147483647) for _ in range(count)],
                    last_index=2147483647, last_start=[1,None,None],
                    last_end=[2147483647,None,None], first_unused=0)

    def _context(self, value):
        if value is None:
            return self.empty_context()
        if not isinstance(value,dict) or type(value.get('version')) is not int or set(value) != {'version','identity','order','stats','last_index','last_start','last_end','first_unused'} or value['version'] != 1 or value['identity'] != self.identity:
            raise ValueError('invalid detector context schema')
        count = len(self.templates)
        if not isinstance(value['order'],list) or any(type(index) is not int for index in value['order']) or len(value['order']) != count or set(value['order']) != set(range(count)) or not isinstance(value['stats'],list) or len(value['stats']) != count:
            raise ValueError('context template identity mismatch')
        if type(value['first_unused']) is not int or not 0 <= value['first_unused'] <= count:
            raise ValueError('invalid unused index')
        if type(value['last_index']) is not int or not (0 <= value['last_index'] < count or value['last_index'] == 2147483647):
            raise ValueError('invalid last index')
        for boundary in (value['last_start'],value['last_end']):
            if not isinstance(boundary,list) or len(boundary) != 3 or type(boundary[0]) is not int or not 0 <= boundary[0] <= 2147483647:
                raise ValueError('invalid date boundary')
            if any(character is not None and (not isinstance(character,str) or len(character)>1) for character in boundary[1:]):
                raise ValueError('invalid boundary character')
        for stat in value['stats']:
            if not isinstance(stat,dict) or set(stat) != {'hits','match_hits','used','distance'} or type(stat['hits']) is not int or not 0 <= stat['hits'] < 2**63-1 or type(stat['match_hits']) is not int or not 0 <= stat['match_hits'] < 2**63-1 or type(stat['used']) not in (int,float) or not math.isfinite(stat['used']) or type(stat['distance']) is not int or not 0 <= stat['distance'] <= 2147483647:
                raise ValueError('invalid template statistics')
        return json.loads(json.dumps(value, allow_nan=False))

    def process(self, line, *, now, usage_time, context=None):
        if not math.isfinite(now) or not math.isfinite(usage_time):
            raise ValueError('nonfinite detector clock')
        saved = self._context(context)
        order, stats = saved['order'], saved['stats']
        last = saved['last_index']
        found = None
        ignored = None
        reserved = None
        if last < len(order):
            template = self.templates[order[last]]
            if template.anchored:
                match = template.match(line)
                ignored = last
            else:
                start, previous_before, previous_inside = saved['last_start']
                end, previous_end_inside, previous_after = saved['last_end']
                left_same = line[start-1:start] == previous_before or (previous_inside is not None and line[start:start+1] == previous_inside and not previous_inside.isalnum())
                right_same = line[end:end+1] == previous_after or (previous_end_inside is not None and line[end-1:end] == previous_end_inside and not previous_end_inside.isalnum())
                if left_same and right_same:
                    match = template.match(line,start,end)
                else:
                    match = template.match(line)
                    ignored = last
            if match:
                stats[order[last]]['match_hits'] += 1
                if len(order)==1 or template.anchored or (match.start()==saved['last_start'][0] and match.end()==saved['last_end'][0]):
                    found = (last,match)
                else:
                    reserved = (last,match)
        if found is None:
            for index, identity in enumerate(order):
                if index == ignored:
                    continue
                template = self.templates[identity]
                match = template.match(line)
                if not match:
                    continue
                stats[identity]['match_hits'] += 1
                distance = match.start()
                if index+1 == len(order) or template.anchored or (distance==0 and stats[identity]['hits'] and not stats[order[index+1]]['match_hits']):
                    found = (index,match)
                    break
                if distance > stats[identity]['distance'] or distance > saved['last_start'][0]:
                    if reserved is None or distance < reserved[1].start():
                        reserved = (index,match)
                    continue
                found = (index,match)
                break
            if found is None:
                found = reserved
        if found is None:
            return None,saved
        index,match = found
        identity = order[index]
        stat = stats[identity]
        stat['hits'] += 1
        stat['used'] = usage_time
        stat['distance'] = match.start()
        if saved['first_unused'] == index:
            saved['first_unused'] += 1
        start,end = match.span()
        saved['last_start'] = [start,line[start-1:start],line[start:start+1]]
        saved['last_end'] = [end,line[end-1:end],line[end:end+1]]
        if index and index != last:
            target = saved['first_unused'] if saved['first_unused'] < index else index//2
            def can_move(position):
                other = stats[order[position]]
                own_weight = stat['hits']*self.templates[identity].weight/max(1,stat['distance'])
                other_weight = other['hits']*self.templates[order[position]].weight/max(1,other['distance'])
                return own_weight > other_weight or stat['used']-300 > other['used']
            if not can_move(target):
                target = index-1
            if can_move(target):
                order.insert(target,order.pop(index))
                index = target
                while saved['first_unused'] < len(order) and stats[order[saved['first_unused']]]['hits']:
                    saved['first_unused'] += 1
        saved['last_index'] = index
        return self.templates[identity].decode(match,now=now,default_tz=self.default_tz),saved
