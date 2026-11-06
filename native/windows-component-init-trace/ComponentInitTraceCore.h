#pragma once
#include <atomic>
#include <cstdint>
#include <cstring>
#include <utility>

namespace cfx::component_init_trace {
enum : unsigned { Seen = 1, Before = 2, Returned = 3, Complete = 4, BudgetExhausted = 5, ClassificationFailed = 6 };

template<class Platform> class Observer {
  inline static std::atomic<unsigned> lines{0};
  inline static std::atomic<unsigned> seen{0};
  struct PreserveError {
    decltype(Platform::GetError()) value = Platform::GetError();
    ~PreserveError() { Platform::SetError(value); }
  };
  static unsigned Emit(unsigned event, unsigned component, unsigned ordinal, unsigned call, unsigned value) {
    PreserveError preserve;
    unsigned previous = lines.load(std::memory_order_relaxed);
    while (previous < 128 && !lines.compare_exchange_weak(previous, previous + 1, std::memory_order_relaxed)) {}
    if (previous >= 128) return 0;
    const unsigned sequence = previous + 1;
    if (sequence == 128) {
      Platform::Write(sequence, BudgetExhausted, 0, 0, 0, 1);
      return 0;
    }
    if (event == Before) call = sequence;
    Platform::Write(sequence, event, component, ordinal, call, value);
    return sequence;
  }
public:
  static bool Enabled() {
    PreserveError preserve;
    return Platform::EnabledExact();
  }
  static unsigned Id(const char* name) {
    if (!std::strcmp(name, "sticky")) return 1;
    if (!std::strcmp(name, "adhesive")) return 2;
    if (!std::strcmp(name, "net")) return 3;
    if (!std::strcmp(name, "glue")) return 4;
    if (!std::strcmp(name, "legitimacy")) return 5;
    if (!std::strcmp(name, "nui:core")) return 6;
    return 0;
  }
  template<class GetName> static unsigned ResolveId(GetName&& getName) {
    PreserveError preserve;
    unsigned id = 0;
    try {
      // The temporary name is destroyed before PreserveError restores LastError.
      auto name = std::forward<GetName>(getName)();
      id = Id(name.c_str());
    } catch (...) {
      Emit(ClassificationFailed, 0, 0, 0, 1);
    }
    return id;
  }
  static void ComponentSeen(unsigned id, bool hasInstances) {
    PreserveError preserve;
    if (!id) return;
    seen.fetch_or(1u << (id - 1), std::memory_order_relaxed);
    Emit(Seen, id, 0, 0, hasInstances);
  }
  template<class Initialize> static void Invoke(unsigned id, unsigned ordinal, Initialize&& initialize) {
    if (!id) {
      std::forward<Initialize>(initialize)();
      return;
    }
    const unsigned call = Emit(Before, id, ordinal, 0, 1);
    const bool result = std::forward<Initialize>(initialize)();
    Emit(Returned, id, ordinal, call, result);
  }
  static void Finish() {
    Emit(Complete, 0, 0, 0, seen.load(std::memory_order_relaxed));
  }
};
}
