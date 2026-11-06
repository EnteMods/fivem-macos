#include <StdInc.h>
#include <ComponentLoader.h>

class NativeFixture final : public Component
{
public:
    bool SetUserData(const std::string& value) override { return value == "native-fixture-test"; }
    bool Shutdown() override { return true; }
};

extern "C" DLL_EXPORT Component* CreateComponent()
{
    return new NativeFixture();
}
