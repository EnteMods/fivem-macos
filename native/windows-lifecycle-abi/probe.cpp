#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <boost/type_index.hpp>
#include <cstdio>
#include "ObservedPublic.inc"

class LocalLifeCycle final : public LifeCycleComponent
{
public:
    unsigned calls = 0;
    void PreResumeGame() override { ++calls; }
    void PreInitGame() override {}
    void HandleAbnormalTermination(void*) override {}
};

class LocalComponent
{
public:
    LocalLifeCycle lifecycle;
    unsigned query = 0;
    bool IsA(uint32_t type)
    {
        query = type;
        return type == HashString("LifeCycleComponent");
    }
    void* As(uint32_t type)
    {
        return type == HashString("LifeCycleComponent") ? &lifecycle : nullptr;
    }
};

int main()
{
    const auto pretty = boost::typeindex::type_id<LifeCycleComponent>().pretty_name();
    const auto stripped = pretty.substr(6);
    const auto expected = HashString("LifeCycleComponent");
    const auto calculated = HashString(stripped.c_str());
    LocalComponent component;
    auto lifecycle = dynamic_component_cast<LifeCycleComponent*>(&component);
    if (lifecycle)
    {
        lifecycle->PreResumeGame();
    }
    const bool passed = calculated == expected && component.query == expected &&
                        lifecycle == &component.lifecycle && component.lifecycle.calls == 1;
    std::printf("LIFECYCLE_ABI %u %u %u %u %u %u\n", expected, calculated,
                component.query, lifecycle != nullptr, component.lifecycle.calls, passed);
    return passed ? 0 : 1;
}
