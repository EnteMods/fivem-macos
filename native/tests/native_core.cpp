#include <StdInc.h>
#include <ComponentLoader.h>
#include <DllGameComponent.h>
#include <console/Console.h>
#include <console/Console.Variables.h>
#include <se/Security.h>
#include <SHA1.h>
#include <pthread.h>
#include <iostream>
#include <stdexcept>

extern "C" void CfxNativeRunCoreInitializersForTests();

static void Require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

int main(int argc, char** argv)
{
    if (argc == 2 && std::string(argv[1]) == "--initialize-client")
    {
        ComponentLoader::GetInstance()->InitializeWithString("[]");
        return 0;
    }
    CfxNativeRunCoreInitializersForTests();
    Require(IsRunningTests(), "Executable test detection failed");
    const auto root = GetAbsoluteCitPath();
    Require(!root.empty() && root.back() == '/' && root.front() == '/', "Invalid executable root path");
    const std::wstring text = L"München 🎮";
    Require(ToWide(ToNarrow(text)) == text, "UTF conversion failed");
    SetThreadName(-1, "CfxNativeCoreTest");
    char name[64] = {};
    Require(pthread_getname_np(pthread_self(), name, sizeof(name)) == 0 && std::string(name) == "CfxNativeCoreTest", "Darwin thread naming failed");
    const auto requested = ComponentId::Parse("native:fixture[1.2.0.0]");
    const auto provided = ComponentId::Parse("native:fixture[1.2.3.0]");
    Require(requested.IsMatchedBy(provided), "Component version matching failed");
    Require(CoreGetComponentRegistry()->RegisterComponent("native-test") == CoreGetComponentRegistry()->RegisterComponent("native-test"), "Component registry identity failed");
    auto context = console::GetDefaultContext();
    int value = 0;
    auto command = std::make_unique<ConsoleCommand>(context, "native_probe", [&value](int input) { value = input; });
    context->ExecuteSingleCommand("native_probe 42");
    Require(value == 0, "Unprivileged native console command was accepted");
    {
        se::ScopedPrincipal principal(se::Principal{ "system.console" });
        context->ExecuteSingleCommand("native_probe 42");
    }
    Require(value == 42, "Authorized native console dispatch failed");
    DllGameComponent fixture("libnative-fixture.dylib");
    Require(fixture.GetName() == "native:fixture", "Native fixture manifest failed");
    auto instance = fixture.CreateInstance("native-fixture-test");
    Require(instance.GetRef() != nullptr && instance->Initialize(), "Native fixture dlopen/CreateComponent failed");
    Require(instance->Shutdown(), "Native fixture shutdown failed");
    Require(fixture.CreateInstance("invalid-test-input").GetRef() == nullptr, "Component user data rejection failed");
    std::cout << "Native core APIs passed; client/security/game initialization remains unavailable.\n";
    return 0;
}
