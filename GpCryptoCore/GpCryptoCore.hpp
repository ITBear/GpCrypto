#pragma once

#include <GpCrypto/GpCryptoCore/GpCryptoCore_global.hpp>
#include <GpCore2/GpUtils/Macro/GpMacroClass.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoCore
{
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoCore)

public:
    static void         SInit                   (void);
    static void         SClear                  (void);

private:
    static void         SCheckEntropyCapacity   (void);
};

}// namespace GPlatform
