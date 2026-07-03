#pragma once

#include "InjectionDetectionMechanism.h"

#include <memory>
#include <vector>

namespace target
{
using MechanismFactory = std::unique_ptr<IInjectionDetectionMechanism>(*)();

// Process-wide list of detection mechanism factories.
//
// Concrete mechanisms self-register at static initialization time using
// TARGET_REGISTER_MECHANISM. The UI then asks the registry to create one fresh
// instance of each row. This keeps MainWindow free of a hardcoded list and makes
// adding a new teaching check a small, local change.
class MechanismRegistry
{
public:
    static MechanismRegistry& Instance();

    void RegisterFactory(MechanismFactory factory);
    std::vector<std::unique_ptr<IInjectionDetectionMechanism>> CreateMechanisms() const;

private:
    std::vector<MechanismFactory> factories_;
};

// Helper used by TARGET_REGISTER_MECHANISM.
//
// The registrar stores a factory function rather than a mechanism object. That
// lets the UI create the rows after the window exists, and it avoids sharing
// state across accidental test runs.
template <typename T>
class MechanismRegistrar
{
public:
    MechanismRegistrar()
    {
        MechanismRegistry::Instance().RegisterFactory(&Create);
    }

private:
    static std::unique_ptr<IInjectionDetectionMechanism> Create()
    {
        return std::make_unique<T>();
    }
};
}

#define TARGET_JOIN_TOKENS_INNER(left, right) left##right
#define TARGET_JOIN_TOKENS(left, right) TARGET_JOIN_TOKENS_INNER(left, right)
#define TARGET_REGISTER_MECHANISM(TypeName) \
    namespace { const ::target::MechanismRegistrar<TypeName> TARGET_JOIN_TOKENS(g_mechanism_registrar_, __COUNTER__); }
