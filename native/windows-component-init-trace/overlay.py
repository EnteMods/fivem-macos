"""Create a separate CitizenGame source overlay; never modify the source snapshot."""
import hashlib
from pathlib import Path

BASE_SHA = 'f0a76129639e1254605bc07ab93013da3c03a7f94384ced4feec214085953859'

def adapt(data):
    if hashlib.sha256(data).hexdigest() != BASE_SHA:
        raise ValueError('Exact existing 88a4 CitizenGame source required')
    newline = b'\r\n' if b'\r\n' in data else b'\n'
    old = b'''        ComponentLoader::GetInstance()->ForAllComponents([&] (fwRefContainer<ComponentData> componentData)
        {
            for (auto& instance : componentData->GetInstances())
            {
                instance->Initialize();
            }
        });'''.replace(b'\n', newline)
    new = b'''        const bool traceInitializations = cfx::component_init_trace::Trace::Enabled();
        ComponentLoader::GetInstance()->ForAllComponents([&] (fwRefContainer<ComponentData> componentData)
        {
            if (traceInitializations)
            {
                const unsigned componentId = cfx::component_init_trace::Trace::ResolveId([&]() { return componentData->GetName(); });
                const auto& instances = componentData->GetInstances();
                cfx::component_init_trace::Trace::ComponentSeen(componentId, !instances.empty());
                unsigned ordinal = 0;
                for (auto& instance : instances)
                {
                    cfx::component_init_trace::Trace::Invoke(componentId, ++ordinal, [&]() { return instance->Initialize(); });
                }
            }
            else
            {
            for (auto& instance : componentData->GetInstances())
            {
                instance->Initialize();
            }
            }
        });
        if (traceInitializations)
        {
            cfx::component_init_trace::Trace::Finish();
        }'''.replace(b'\n', newline)
    include = b'#include <StartupPhaseTrace.h>'
    if data.count(old) != 1 or data.count(include) != 1:
        raise ValueError('Expected unique original initialization block and existing startup diagnostics')
    result = data.replace(include, include + newline + b'#include "ComponentInitTrace.h"', 1).replace(old, new, 1)
    if result.replace(new, old, 1).replace(include + newline + b'#include "ComponentInitTrace.h"', include, 1) != data:
        raise ValueError('Overlay must strip exactly to original source')
    return result
