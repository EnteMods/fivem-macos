"""Observe class identity after existing Wine name resolution, without another lookup."""

from overlay import EX_TRACE, HELPERS


HELPER = '''
static unsigned int trace_name_kind( const UNICODE_STRING *name, const WCHAR *buffer )
{
    static const WCHAR target[] = L"grcwindow";
    unsigned int units, suffix, i;

    if (!TRACE_ON(cfxwndreg) || name->Buffer != buffer || name->Length > name->MaximumLength ||
        name->Length % sizeof(WCHAR)) return 0;
    units = name->Length / sizeof(WCHAR);
    if (units < ARRAY_SIZE(target) - 1) return 0;
    suffix = units - (ARRAY_SIZE(target) - 1);
    for (i = 0; i < ARRAY_SIZE(target) - 1; i++)
    {
        WCHAR ch = buffer[suffix + i];
        if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
        if (ch != target[i]) return 0;
    }
    return !suffix ? 1 : buffer[suffix - 1] == '!' ? 2 : 0;
}

static void trace_class_resolution( unsigned int role, const UNICODE_STRING *name, const WCHAR *buffer,
                                    const UNICODE_STRING *version, BOOL atom_input )
{
    struct cfx_numeric_saved saved = cfx_numeric_save();
    TRACE_(cfxwndreg)( "role=%u kind=%u units=%u prefix=%u atom_input=%u\\n", role,
                       trace_name_kind( name, buffer ), (unsigned int)(name->Length / sizeof(WCHAR)),
                       (unsigned int)(version->Length / sizeof(WCHAR)), !!atom_input );
    cfx_numeric_restore( &saved );
}

static void trace_class_removal( BOOL result )
{
    struct cfx_numeric_saved saved = cfx_numeric_save();
    TRACE_(cfxwndreg)( "ok=%u error=%lu\\n", !!result, result ? 0 : saved.api_error );
    cfx_numeric_restore( &saved );
}

static void trace_class_atom( ATOM atom )
{
    struct cfx_numeric_saved saved = cfx_numeric_save();
    TRACE_(cfxwndreg)( "atom=%u\\n", (unsigned int)atom );
    cfx_numeric_restore( &saved );
}
'''
UNREGISTER = '''    BOOL ret;

    init_class_name( &name, class_name );
    get_class_version( &name, &version, FALSE );

    ret = NtUserUnregisterClass( &name, instance, &menu_name );
    if (ret) free_menu_name( &menu_name );
    return ret;
'''
UNREGISTER_TRACED = '''    BOOL ret, selected;

    init_class_name( &name, class_name );
    selected = !!trace_name_kind( &name, nameW );
    get_class_version( &name, &version, FALSE );
    if (selected || trace_name_kind( &name, nameW ))
    {
        selected = TRUE;
        trace_class_resolution( 2, &name, nameW, &version, IS_INTRESOURCE(class_name) );
    }

    ret = NtUserUnregisterClass( &name, instance, &menu_name );
    if (ret) free_menu_name( &menu_name );
    if (selected) trace_class_removal( ret );
    return ret;
'''


def apply(original):
    register = EX_TRACE.replace('    get_class_version( &name, &version, FALSE );\n',
        '    get_class_version( &name, &version, FALSE );\n'
        '    if (selected) trace_class_resolution( 1, &name, nameW, &version, IS_INTRESOURCE(wc->lpszClassName) );\n')
    register = register.replace('    if (selected) trace_registration( 4, atom );\n',
        '    if (selected)\n'
        '    {\n'
        '        trace_class_atom( atom );\n'
        '        trace_registration( 4, atom );\n'
        '    }\n')
    edits = ((HELPERS, HELPERS + HELPER), (EX_TRACE, register), (UNREGISTER, UNREGISTER_TRACED))
    modified = original
    for before, after in edits:
        if modified.count(before.encode()) != 1:
            raise ValueError('Unexpected Wine class-resolution source boundary')
        modified = modified.replace(before.encode(), after.encode(), 1)
    restored = modified
    for before, after in reversed(edits):
        restored = restored.replace(after.encode(), before.encode(), 1)
    if restored != original:
        raise ValueError('Class-resolution overlay must roundtrip to the original diagnostic source')
    return modified
