#include "ComponentInitTraceCore.h"
#include <algorithm>
#include <cassert>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <cstdio>

struct Row { unsigned seq, event, component, ordinal, call, value; };
struct FixturePlatform {
  inline static thread_local unsigned error = 0;
  inline static std::string option;
  inline static std::mutex lock;
  inline static std::vector<Row> rows;
  static unsigned GetError() { return error; }
  static void SetError(unsigned value) { error = value; }
  static bool EnabledExact() { error = 0xf00; return option == "1"; }
  static void Write(unsigned s, unsigned e, unsigned c, unsigned o, unsigned call, unsigned v) {
    std::lock_guard guard(lock);
    rows.push_back({s,e,c,o,call,v});
    error = 0xbaad;
  }
};
namespace cfx::component_init_trace { using Trace = Observer<FixturePlatform>; }
using Trace = cfx::component_init_trace::Trace;

struct Name {
  std::string text;
  const char* c_str() const { return text.c_str(); }
  ~Name() { FixturePlatform::error = 0x12345; }
};
struct Instance {
  bool result = true, throws = false;
  unsigned calls = 0, received = 0, produced = 0;
  bool Initialize() {
    ++calls;
    received = FixturePlatform::error;
    FixturePlatform::error = produced;
    if (throws) throw std::runtime_error("own fixture");
    return result;
  }
};
template<class T> using fwRefContainer = std::shared_ptr<T>;
struct ComponentData {
  std::string name;
  bool nameThrows = false;
  unsigned nameCalls = 0, instanceCalls = 0;
  std::vector<std::shared_ptr<Instance>> instances;
  Name GetName() {
    ++nameCalls;
    FixturePlatform::error = 0x11111;
    if (nameThrows) throw std::runtime_error("own metadata fixture");
    return Name{name};
  }
  const auto& GetInstances() { ++instanceCalls; return instances; }
};
struct ComponentLoader {
  inline static std::vector<std::shared_ptr<ComponentData>> components;
  static ComponentLoader* GetInstance() { static ComponentLoader loader; return &loader; }
  template<class Callback> void ForAllComponents(Callback callback) {
    for (const auto& component : components) callback(component);
  }
};
void Loop() {
#include "ObservedBlock.inc"
}
std::shared_ptr<ComponentData> Component(const char* name, std::shared_ptr<Instance> instance) {
  auto component = std::make_shared<ComponentData>();
  component->name = name;
  component->instances.push_back(instance);
  return component;
}
int main() {
  for (const char* option : {"", "0", "01", "true", "11", "1x"}) {
    FixturePlatform::option = option;
    auto instance = std::make_shared<Instance>();
    instance->result = false; instance->produced = 17;
    auto component = Component("sticky", instance);
    ComponentLoader::components = {component}; FixturePlatform::error = 12;
    Loop();
    assert(component->nameCalls == 0 && component->instanceCalls == 1 && instance->calls == 1);
    assert(instance->received == 12 && FixturePlatform::error == 17 && FixturePlatform::rows.empty());
  }
  FixturePlatform::option = "1";
  auto first = std::make_shared<Instance>(); first->result = false; first->produced = 0x222;
  auto second = std::make_shared<Instance>(); second->produced = 0x333;
  auto sticky = Component("sticky", first), nui = Component("nui:core", second);
  ComponentLoader::components = {sticky,nui}; FixturePlatform::error = 0x111;
  Loop();
  assert(first->calls == 1 && second->calls == 1 && sticky->nameCalls == 1 && nui->nameCalls == 1);
  assert(first->received == 0x111 && second->received == 0x222 && FixturePlatform::error == 0x333);
  assert(FixturePlatform::rows.size() == 7);
  assert(FixturePlatform::rows[1].event == 2 && FixturePlatform::rows[2].event == 3);
  assert(FixturePlatform::rows[2].value == 0 && FixturePlatform::rows[5].value == 1);
  assert(FixturePlatform::rows[2].call == FixturePlatform::rows[1].seq);
  assert(FixturePlatform::rows[5].component == 6 && FixturePlatform::rows[6].value == 33);
  assert(Trace::Id("nui-core") == 0 && Trace::Id("net") == 3);

  auto metadataInstance = std::make_shared<Instance>(); metadataInstance->produced = 0x556;
  auto metadata = Component("sticky", metadataInstance); metadata->nameThrows = true;
  ComponentLoader::components = {metadata}; FixturePlatform::error = 0x445;
  const auto metadataStart = FixturePlatform::rows.size(); Loop();
  assert(metadataInstance->calls == 1 && metadataInstance->received == 0x445 && FixturePlatform::error == 0x556);
  assert(FixturePlatform::rows[metadataStart].event == 6);

  auto throwing = std::make_shared<Instance>(); throwing->throws = true; throwing->produced = 0xdead;
  ComponentLoader::components = {Component("net",throwing)}; FixturePlatform::error = 0x777;
  const auto throwStart = FixturePlatform::rows.size();
  try { Loop(); assert(false); } catch (const std::runtime_error&) {}
  assert(throwing->calls == 1 && throwing->received == 0x777 && FixturePlatform::error == 0xdead);
  assert(FixturePlatform::rows.size() == throwStart + 2 && FixturePlatform::rows.back().event == 2);

  std::vector<std::thread> workers;
  for (unsigned thread = 0; thread < 8; ++thread) workers.emplace_back([thread] {
    for (unsigned call = 0; call < 32; ++call) {
      FixturePlatform::error = thread;
      Trace::Invoke(4, call+1, [] { FixturePlatform::error = 0xfac; return true; });
      assert(FixturePlatform::error == 0xfac);
    }
  });
  for (auto& worker : workers) worker.join();
  assert(FixturePlatform::rows.size() == 128);
  std::set<unsigned> sequences;
  unsigned exhausted = 0;
  for (const auto& row : FixturePlatform::rows) {
    assert(sequences.insert(row.seq).second);
    if (row.event == 5) { ++exhausted; assert(row.seq == 128 && row.component == 0 && row.call == 0); }
    if (row.event == 3) assert(row.call > 0 && row.call < row.seq);
  }
  assert(exhausted == 1 && sequences.size() == 128);
  for (unsigned i = 0; i < 10000; ++i) Trace::Invoke(1,1,[] { return false; });
  assert(FixturePlatform::rows.size() == 128);
  std::puts("own_fixture_passed=1 max_lines=128 worker_threads=8");
}
