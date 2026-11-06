#include <StdInc.h>

extern "C" DLL_EXPORT void CfxNativeRunCoreInitializersForTests()
{
    InitFunctionBase::RunAll();
}
