"""Byte-preserving edits to the two GTA video resolution values."""
import re
from typing import NamedTuple
from xml.parsers import expat


class VideoState(NamedTuple):
    width: int
    height: int
    windowed: int


_VIDEO = ['Settings', 'video']
_FIELDS = ('ScreenWidth', 'ScreenHeight', 'Windowed')
_VALUE = re.compile(rb'<(ScreenWidth|ScreenHeight|Windowed)[ \t\r\n]+value[ \t\r\n]*=[ \t\r\n]*'
                    rb'([\'"])(?P<digits>0|[1-9][0-9]{0,4})\2[ \t\r\n]*/?>')
_MAX_EXTENT = 16384
_MAX_BYTES = 256 * 1024


def _valid_extent(value):
    return type(value) is int and 1 <= value <= _MAX_EXTENT


def _scan(data):
    if type(data) is not bytes or not 0 < len(data) <= _MAX_BYTES:
        raise ValueError('Expected bounded video settings bytes')

    parser = expat.ParserCreate(namespace_separator='|')
    stack = []
    fields = {}
    videos = 0

    def start(name, attrs):
        nonlocal videos
        if (not stack and name != 'Settings') or len(stack) >= 64:
            raise ValueError('Unexpected settings XML structure')
        if stack == _VIDEO[:1] and name == 'video':
            videos += 1
            if videos != 1:
                raise ValueError('Ambiguous video settings section')
        if stack == _VIDEO and name in _FIELDS:
            match = _VALUE.match(data, parser.CurrentByteIndex)
            if (name in fields or set(attrs) != {'value'} or not match or match[1].decode('ascii') != name
                    or match['digits'].decode('ascii') != attrs['value']):
                raise ValueError('Ambiguous or unsupported video value')
            fields[name] = int(attrs['value']), match.span('digits')
        if in_value():
            raise ValueError('Video values must be leaves')
        stack.append(name)

    def in_value():
        return len(stack) == 3 and stack[:2] == _VIDEO and stack[2] in _FIELDS

    def character(content):
        if in_value() and content.strip(' \t\r\n'):
            raise ValueError('Unexpected text in video value')

    def forbidden(*_):
        raise ValueError('XML declarations of entities and document types are unsupported')

    parser.StartElementHandler = start
    parser.EndElementHandler = lambda _: stack.pop()
    parser.CharacterDataHandler = character
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    try:
        parser.Parse(data, True)
    except (expat.ExpatError, LookupError) as exc:
        raise ValueError('Malformed or unsupported settings XML') from exc

    if videos != 1 or fields.keys() != set(_FIELDS):
        raise ValueError('Missing video settings values')
    state = VideoState(*(fields[name][0] for name in _FIELDS))
    if not _valid_extent(state.width) or not _valid_extent(state.height) or state.windowed not in (0, 1, 2):
        raise ValueError('Unsupported video settings values')
    return state, tuple(fields[name][1] for name in _FIELDS[:2])


def parse(data: bytes) -> VideoState:
    """Read the single video mode, including fullscreen or borderless states."""
    return _scan(data)[0]


def _replace(data, spans, width, height):
    for (start, end), value in sorted(zip(spans, (width, height)), reverse=True):
        data = data[:start] + str(value).encode('ascii') + data[end:]
    return data


def transform(data: bytes, width: int, height: int) -> bytes:
    """Replace only the two decimal values in a Windowed=1 document."""
    if not _valid_extent(width) or not _valid_extent(height):
        raise ValueError('Unsupported requested video extent')
    state, spans = _scan(data)
    if state.windowed != 1:
        raise ValueError('Resolution change requires Windowed=1')
    return _replace(data, spans, width, height)


def restore(data: bytes, original: VideoState, applied: VideoState) -> bytes:
    """Restore the original pair only while the complete applied mode still matches."""
    for state in (original, applied):
        if (type(state) is not VideoState or not _valid_extent(state.width) or not _valid_extent(state.height)
                or type(state.windowed) is not int or state.windowed != 1):
            raise ValueError('Invalid windowed restoration state')
    current, spans = _scan(data)
    if current == original:
        return data
    if current != applied:
        raise ValueError('Video mode changed after the resolution edit')
    return _replace(data, spans, original.width, original.height)
