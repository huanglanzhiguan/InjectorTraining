#include "MechanismRegistry.h"

namespace target
{
const wchar_t* ToDisplayText(DetectionState state) noexcept
{
    switch (state)
    {
    case DetectionState::NotRun:
        return L"not run";
    case DetectionState::Clean:
        return L"clean";
    case DetectionState::Detected:
        return L"detected";
    case DetectionState::Suspicious:
        return L"suspicious";
    case DetectionState::Error:
        return L"error";
    default:
        return L"unknown";
    }
}

MechanismRegistry& MechanismRegistry::Instance()
{
    static MechanismRegistry registry;
    return registry;
}

void MechanismRegistry::RegisterFactory(MechanismFactory factory)
{
    factories_.push_back(factory);
}

std::vector<std::unique_ptr<IInjectionDetectionMechanism>> MechanismRegistry::CreateMechanisms() const
{
    std::vector<std::unique_ptr<IInjectionDetectionMechanism>> mechanisms;
    mechanisms.reserve(factories_.size());

    for (MechanismFactory factory : factories_)
    {
        mechanisms.push_back(factory());
    }

    return mechanisms;
}
}
