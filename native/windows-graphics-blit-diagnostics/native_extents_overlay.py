"""Keep each native-size axis in the exact sharpness candidate."""
import hashlib


UNIT_PIN = (40240, 'e9133687127896b166409daa88a2da06413d8325f2114e3a97662bcb55eb488e')
HEADER_PIN = (3308, '9260a81b72faed0d9d8279b80e262a6699009f56a66b30d1781b891433790223')

UNIT = tuple((before.replace(b'\n', b'\r\n'), after.replace(b'\n', b'\r\n')) for before, after in (
    (b'struct ProjectionSize\n{\n\tunsigned width = 0, height = 0;\n};',
     b'struct ProjectionSize\n{\n\tunsigned width = 0, height = 0;\n\tbool adjusted = false;\n};'),
    (b'\t\t{\n\t\t\tfor (auto& vertex : pending.vertices)\n'
     b'\t\t\t\tvertex.y += static_cast<float>(geometry.height) - ProjectionReferenceHeight;\n'
     b'\t\t\tsize = {geometry.width, geometry.height};\n\t\t}\n',
     b'\t\t\tsize = {geometry.width, geometry.height, geometry.width < ProjectionReferenceWidth\n'
     b'\t\t\t\t|| geometry.height < ProjectionReferenceHeight};\n'),
    (b'[CFX_GRAPHICS_BLIT_PROJECTION] pid= tid= applied=1 width= height= ref_width= ref_height=\\n") + 60',
     b'[CFX_GRAPHICS_BLIT_PROJECTION] pid= tid= applied= width= height= ref_width= ref_height=\\n") + 61'),
    (b'\tAppend(out, " applied=1 width="); AppendUnsigned(out, size.width);\n',
     b'\tAppend(out, " applied="); AppendUnsigned(out, size.adjusted);\n'
     b'\tAppend(out, " width="); AppendUnsigned(out, size.width);\n'),
))

HEADER = (
    (b'!referenceHeight || referenceHeight > MaxExtent\n            || (width == referenceWidth && height == referenceHeight))',
     b'!referenceHeight || referenceHeight > MaxExtent)'),
    (b'    // Each checked coordinate is either the origin or the full extent. Assigning the\n'
     b'    // reference extent is exactly the desired scaling and avoids floating-point ratio error.\n'
     b'    if (width != referenceWidth)\n'
     b'        vertices[1].x = vertices[3].x = static_cast<float>(referenceWidth);\n'
     b'    if (height != referenceHeight)\n'
     b'        vertices[0].y = vertices[1].y = static_cast<float>(referenceHeight);\n',
     b'    // Keep native axes as supplied. Apply the established projection only to smaller axes.\n'
     b'    if (width < referenceWidth)\n'
     b'        vertices[1].x = vertices[3].x = static_cast<float>(referenceWidth);\n'
     b'    if (height < referenceHeight)\n'
     b'    {\n'
     b'        vertices[0].y = vertices[1].y = static_cast<float>(referenceHeight);\n'
     b'        const auto offset = static_cast<float>(height) - referenceHeight;\n'
     b'        for (auto& vertex : vertices)\n'
     b'            vertex.y += offset;\n'
     b'    }\n'),
)


def require(data, pin):
    if type(data) is not bytes or (len(data), hashlib.sha256(data).hexdigest()) != pin:
        raise ValueError('Require the exact sharpness projection input')


def replace(data, changes):
    for before, after in changes:
        if data.count(before) != 1:
            raise ValueError('Expected one exact native-extents anchor')
        data = data.replace(before, after, 1)
    return data


def apply(unit, header):
    require(unit, UNIT_PIN)
    require(header, HEADER_PIN)
    return replace(unit, UNIT), replace(header, HEADER)


def strip(unit, header):
    originals = tuple(replace(data, ((after, before) for before, after in reversed(changes)))
                      for data, changes in ((unit, UNIT), (header, HEADER)))
    require(originals[0], UNIT_PIN)
    require(originals[1], HEADER_PIN)
    return originals
