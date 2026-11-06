"""Bypass render-state queries for an unchanged native-extent replay."""
import hashlib


UNIT_PIN = (40279, '88914b41253d087549b8828e569330c59ebd0c45eac5aa14198685484892b3bb')
BEFORE = b'\tif (allowScaling && pending.active && pending.count == 4)\r\n'
AFTER = (b'\t// Both native axes are replayed unchanged, regardless of the bound render state.\r\n'
         b'\tif (allowScaling && pending.active && pending.count == 4\r\n'
         b'\t\t&& (pending.vertices[1].x < ProjectionReferenceWidth || pending.vertices[0].y < ProjectionReferenceHeight))\r\n')


def require(data):
    if type(data) is not bytes or (len(data), hashlib.sha256(data).hexdigest()) != UNIT_PIN:
        raise ValueError('Require the exact native-extents projection translation unit')


def apply(data):
    require(data)
    if data.count(BEFORE) != 1:
        raise ValueError('Expected one native-extents replay guard')
    return data.replace(BEFORE, AFTER, 1)


def strip(data):
    if data.count(AFTER) != 1:
        raise ValueError('Expected one native-extents fast replay guard')
    original = data.replace(AFTER, BEFORE, 1)
    require(original)
    return original
