#pragma once

#include <GpCrypto/GpCryptoCore/GpCryptoCore_global.hpp>
#include <GpCore2/GpUtils/Types/Enums/GpEnum.hpp>

namespace GPlatform {

GP_ENUM(GP_CRYPTO_CORE_API, GpCryptoEncryptKeyType,
    X_25519             //Elliptic Curve Diffie-Hellman (ECDH) over Curve25519
);

}// namespace GPlatform
