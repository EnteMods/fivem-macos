#define ABI_FIXTURE_BUILD
#include "interface.h"
#include <windows.h>
#include <intrin.h>
#include <stdexcept>
#include <algorithm>
#include <Win32Intrinsics.h>

class Fixture final : public AbiFixture
{
public:
    std::string Describe() const override { return "dll:" + std::string(128, 'x'); }
    std::vector<std::uint64_t> Transform(std::vector<std::uint64_t> values) const override
    {
        std::reverse(values.begin(), values.end());
        for (auto& value : values) value *= 3;
        values.reserve(128);
        return values;
    }
    void Raise() const override { throw std::runtime_error("dll-exception:" + std::string(96, 'e')); }
    bool CatchHostException(void (*callback)()) const override
    {
        try { callback(); }
        catch (const std::logic_error& error) { return std::string(error.what()) == "host-exception:" + std::string(96, 'h'); }
        return false;
    }
    AbiShape Shape() const override
    {
#ifdef _DLL
        constexpr unsigned dynamicCrt = 1;
#else
        constexpr unsigned dynamicCrt = 0;
#endif
        return {sizeof(void*), sizeof(std::string), sizeof(std::vector<std::uint64_t>), _ITERATOR_DEBUG_LEVEL, _MSC_VER, dynamicCrt};
    }
    bool RoundTripGs() const override
    {
        const auto teb = __readgsqword(0x30);
        const auto original = __readgsqword(0x38);
        constexpr unsigned __int64 value = 0x0123456789abcdef;
        cfx::compat::WriteGsQword(0x38, value);
        const auto observed = __readgsqword(0x38);
        cfx::compat::WriteGsQword(0x38, original);
        return teb != 0 && teb == reinterpret_cast<unsigned __int64>(NtCurrentTeb()) &&
            observed == value && __readgsqword(0x38) == original && __readgsqword(0x30) == teb;
    }
};
extern "C" ABI_PUBLIC AbiFixture* CreateAbiFixture() { return new Fixture(); }
extern "C" ABI_PUBLIC void DestroyAbiFixture(AbiFixture* instance) { delete instance; }
