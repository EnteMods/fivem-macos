#include <StdInc.h>
#include <ComponentLoader.h>
#include <ToolComponent.h>
#include <cstdio>
#include <cstdlib>

class ProbeCommand final : public ToolCommand
{
    boost::program_options::options_description options{"Probe fixture"};
public:
    void SetupCommandLineParser(boost::program_options::wcommand_line_parser& parser,
        std::function<void(boost::program_options::wcommand_line_parser&)> callback) override
    {
        options.add_options()("value", boost::program_options::value<int>()->required(), "Fixture input");
        parser.options(options);
        callback(parser);
    }
    void InvokeCommand(const boost::program_options::variables_map& variables) override
    {
        const auto value = variables["value"].as<int>();
        if (value != 42) { std::fprintf(stderr, "CITICON_FIXTURE_BAD_INPUT\n"); std::exit(93); }
        std::printf("CITICON_UPSTREAM_TOOL_DISPATCH_OK value=%d\n", value);
    }
};

class ProbeComponent final : public Component, public ToolComponent
{
public:
    bool Initialize() override
    {
        std::printf("CITICON_FIXTURE_INITIALIZED\n");
        return true;
    }
    bool Shutdown() override { return true; }
    std::vector<std::string> GetCommandNames() override { return {"probe:dispatch"}; }
    fwRefContainer<ToolCommand> GetCommand(const std::string& command) override
    {
        return command == "probe:dispatch" ? new ProbeCommand() : nullptr;
    }
    bool IsA(uint32_t type) override { return type == HashString("ToolComponent") || Component::IsA(type); }
    void* As(uint32_t type) override
    {
        return type == HashString("ToolComponent") ? static_cast<ToolComponent*>(this) : Component::As(type);
    }
};
extern "C" DLL_EXPORT Component* CreateComponent() { return new ProbeComponent(); }
