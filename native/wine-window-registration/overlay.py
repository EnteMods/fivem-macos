"""Insert an opt-in diagnostic at the unchanged Wine wide-class boundary."""

import hashlib


BASE_SHA256 = '5f1b7f1db78acf55dbc05cb9364abaf50f37fe233ca2f21f0c9d969bad7af98c'
DECLARATION = '''WINE_DEFAULT_DEBUG_CHANNEL(class);
'''
HELPERS = '''WINE_DEFAULT_DEBUG_CHANNEL(class);

#define CFX_NUMERIC_DIAGNOSTICS
#include "cfx_numeric.h"
WINE_DECLARE_DEBUG_CHANNEL(cfxwndreg);

static BOOL trace_grc_registration( const UNICODE_STRING *name, const WCHAR *buffer )
{
    static const WCHAR expected[] = L"grcwindow";
    unsigned int i;

    if (!TRACE_ON(cfxwndreg) || name->Buffer != buffer || name->Length != sizeof(expected) - sizeof(WCHAR))
        return FALSE;
    for (i = 0; i < ARRAY_SIZE(expected) - 1; i++)
    {
        WCHAR ch = buffer[i];
        if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
        if (ch != expected[i]) return FALSE;
    }
    return TRUE;
}

static void trace_registration( unsigned int phase, ATOM atom )
{
    struct cfx_numeric_saved saved;

    if (!TRACE_ON(cfxwndreg)) return;
    saved = cfx_numeric_save();
    TRACE_(cfxwndreg)( "phase=%u ok=%u error=%lu\\n", phase, !!atom,
                       !atom && phase >= 3 ? saved.api_error : 0 );
    cfx_numeric_restore( &saved );
}
'''
W_RETURN = '    return RegisterClassExW( &wcex );\n'
W_TRACE = '''    trace_registration( 1, 0 );
    atom = RegisterClassExW( &wcex );
    trace_registration( 5, atom );
    return atom;
'''
EX_BODY = '''    ATOM atom;

    init_class_name( &name, wc->lpszClassName );
    get_class_version( &name, &version, FALSE );

    if (!alloc_menu_nameW( &menu_name, wc->lpszMenuName )) return 0;

    atom = NtUserRegisterClassExWOW( wc, &name, &version, &menu_name, 0, 0, NULL );
    if (!atom) free_menu_name( &menu_name );
    return atom;
'''
EX_TRACE = '''    ATOM atom;
    BOOL selected;

    init_class_name( &name, wc->lpszClassName );
    selected = trace_grc_registration( &name, nameW );
    if (selected) trace_registration( 2, 0 );
    get_class_version( &name, &version, FALSE );

    if (!alloc_menu_nameW( &menu_name, wc->lpszMenuName ))
    {
        if (selected) trace_registration( 3, 0 );
        return 0;
    }

    atom = NtUserRegisterClassExWOW( wc, &name, &version, &menu_name, 0, 0, NULL );
    if (!atom) free_menu_name( &menu_name );
    if (selected) trace_registration( 4, atom );
    return atom;
'''


def apply(original):
    if hashlib.sha256(original).hexdigest() != BASE_SHA256:
        raise ValueError('Require the reviewed Wine class.c')
    edits = (
        (DECLARATION, HELPERS),
        ('ATOM WINAPI RegisterClassW( const WNDCLASSW* wc )\n{\n    WNDCLASSEXW wcex;\n',
         'ATOM WINAPI RegisterClassW( const WNDCLASSW* wc )\n{\n    WNDCLASSEXW wcex;\n    ATOM atom;\n'),
        (W_RETURN, W_TRACE),
        (EX_BODY, EX_TRACE),
    )
    modified = original
    for before, after in edits:
        if modified.count(before.encode()) != 1:
            raise ValueError('Unexpected Wine registration overlay boundary')
        modified = modified.replace(before.encode(), after.encode(), 1)
    restored = modified
    for before, after in reversed(edits):
        if restored.count(after.encode()) != 1:
            raise ValueError('Registration overlay cannot be reversed')
        restored = restored.replace(after.encode(), before.encode(), 1)
    if restored != original:
        raise ValueError('Registration overlay does not preserve the original source')
    return modified
