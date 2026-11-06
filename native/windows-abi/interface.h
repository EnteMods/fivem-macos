#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct AbiShape
{
    unsigned pointerSize;
    unsigned stringSize;
    unsigned vectorSize;
    unsigned iteratorDebug;
    unsigned msvc;
    unsigned dynamicCrt;
};

class AbiFixture
{
public:
    virtual ~AbiFixture() = default;
    virtual std::string Describe() const = 0;
    virtual std::vector<std::uint64_t> Transform(std::vector<std::uint64_t> values) const = 0;
    virtual void Raise() const = 0;
    virtual bool CatchHostException(void (*callback)()) const = 0;
    virtual AbiShape Shape() const = 0;
    virtual bool RoundTripGs() const = 0;
};

#ifdef ABI_FIXTURE_BUILD
#define ABI_PUBLIC __declspec(dllexport)
#else
#define ABI_PUBLIC __declspec(dllimport)
#endif
extern "C" ABI_PUBLIC AbiFixture* CreateAbiFixture();
extern "C" ABI_PUBLIC void DestroyAbiFixture(AbiFixture* instance);
