#include "interface.h"
#include <windows.h>
#include <intrin.h>
#include <cstdio>
#include <stdexcept>
#include <memory>
#include <Win32Intrinsics.h>

static void Require(bool condition, const char* text)
{
    if (!condition) throw std::runtime_error(text);
}
static void RaiseFromHost() { throw std::logic_error("host-exception:" + std::string(96, 'h')); }
int main()
{
    try
    {
        std::unique_ptr<AbiFixture, decltype(&DestroyAbiFixture)> instance(CreateAbiFixture(), &DestroyAbiFixture);
        Require(instance.get() != nullptr, "DLL factory failed");
        const auto shape = instance->Shape();
        Require(shape.pointerSize == sizeof(void*) && shape.stringSize == sizeof(std::string) &&
            shape.vectorSize == sizeof(std::vector<std::uint64_t>) && shape.iteratorDebug == _ITERATOR_DEBUG_LEVEL &&
            shape.msvc == _MSC_VER && shape.dynamicCrt == 1, "DLL ABI shape mismatch");
        std::string description = instance->Describe();
        Require(description == "dll:" + std::string(128, 'x'), "Cross-DLL returned heap string mismatch");
        description.append(256, 'y');
        std::vector<std::uint64_t> values{1, 2, 9};
        auto result = instance->Transform(values);
        Require(result == std::vector<std::uint64_t>({27, 6, 3}) && values == std::vector<std::uint64_t>({1, 2, 9}), "Cross-DLL vector mismatch");
        bool caught = false;
        try { instance->Raise(); }
        catch (const std::runtime_error& error) { caught = std::string(error.what()) == "dll-exception:" + std::string(96, 'e'); }
        Require(caught, "DLL exception was not caught in host with correct type/data");
        Require(instance->CatchHostException(&RaiseFromHost), "Host exception was not caught inside DLL");
        const auto original = __readgsqword(0x38);
        Require(instance->RoundTripGs() && __readgsqword(0x38) == original, "DLL GS roundtrip/restore failed");
        constexpr unsigned __int64 marker = 0xfedcba9876543210;
        cfx::compat::WriteGsQword(0x38, marker);
        const auto observed = __readgsqword(0x38);
        cfx::compat::WriteGsQword(0x38, original);
        Require(observed == marker && __readgsqword(0x38) == original, "Host GS roundtrip/restore failed");
        std::printf("MD_DLL_ABI_OK ptr=%u msvc=%u iterator=%u string=%u vector=%u dynamic_crt=%u GS38_restored=1\n",
            shape.pointerSize, shape.msvc, shape.iteratorDebug, shape.stringSize, shape.vectorSize, shape.dynamicCrt);
        for (const char* name : {"msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll", "ucrtbase.dll"})
        {
            const auto module = GetModuleHandleA(name);
            if (module)
            {
                char path[1024] = {};
                GetModuleFileNameA(module, path, sizeof(path));
                std::printf("RUNTIME_MODULE %s %s\n", name, path);
            }
        }
        return 0;
    }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "MD_DLL_ABI_FAIL %s\n", error.what());
        return 1;
    }
}
