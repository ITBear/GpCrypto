#pragma once

#include <GpCrypto/GpCryptoUtils/GpCryptoUtils_global.hpp>
#include <GpCore2/GpUtils/Macro/GpMacroClass.hpp>
#include <GpCore2/GpUtils/Types/Containers/GpBytesArray.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Hmac.hpp>

namespace GPlatform {

class GP_CRYPTO_UTILS_API GpCryptoSASLScram
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoSASLScram)

    enum class HashTypeT
    {
        SHA_256
    };

    enum class KeyDerivationFnT
    {
        PBKDF2
    };

    using SmallContainerT       = boost::container::small_vector<std_byte_no_init, 128>;
    using ParseServerFirstResT  = std::tuple<SmallContainerT/*serverNonce*/, SmallContainerT/*salt*/, size_t/*iterations count*/>;

public:
                                GpCryptoSASLScram       (HashTypeT          aHashType,
                                                         KeyDerivationFnT   aKeyDerivationFn) noexcept;
                                ~GpCryptoSASLScram      (void) noexcept;

    SmallContainerT             ClientFirstMessage      (GpSpanByteR aUserName);
    SmallContainerT             ClientFinalMessage      (GpSpanByteR aServerFirstMessage,
                                                         GpSpanByteR aPassword);
    SmallContainerT             ServerFirstMessage      (GpSpanByteR aClientFirstMessage);
    void                        ValidateServerFinal     (GpSpanByteR aServerFinalMessage);

private:
    void                        GenerateNonce           (void);
    ParseServerFirstResT        ParseServerFirstMessage (GpSpanByteR aServerFirstMessage);
    GpSpanByteR                 ParseServerFinalMessage (GpSpanByteR aServerFinalMessage);

private:
    HashTypeT                   iHashType;
    KeyDerivationFnT            iKeyDerivationFn;
    SmallContainerT             iNonce;
    SmallContainerT             iClientFirstWithoutHeader;
    GpCryptoHash_Hmac::Res256T  iClientKey;
    GpCryptoHash_Hmac::Res256T  iServerKey;
    SmallContainerT             iAuthMessage;
};

}// namespace GPlatform
