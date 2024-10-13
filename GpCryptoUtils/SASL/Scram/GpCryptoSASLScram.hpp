#pragma once

#include <GpCrypto/Config/GpConfigCrypto.hpp>
#include <GpCrypto/GpCryptoUtils/GpCryptoUtils_global.hpp>
#include <GpCore2/GpUtils/Macro/GpMacroClass.hpp>
#include <GpCore2/GpUtils/Types/Containers/GpBytesArray.hpp>
#include <GpCrypto/GpCryptoCore/Hashes/GpCryptoHash_Hmac.hpp>

namespace GPlatform {

class GP_CRYPTO_UTILS_API GpCryptoSASLScram
{
public:
    CLASS_REMOVE_CTRS_DEFAULT_MOVE_COPY(GpCryptoSASLScram)
    CLASS_DD(GpCryptoSASLScram)

    enum class HashTypeT
    {
        SHA_256
    };

    enum class KeyDerivationFnT
    {
        PBKDF2
    };

    using SmallContainerT       = boost::container::small_vector<std_byte_no_init, 128>;
    using ParseServerFirstResT  = std::tuple<std::string_view/*serverNonce*/, std::string_view/*clientNonceFromServer*/, SmallContainerT/*salt*/, size_t/*iterations count*/>;
    using ParseClientFirstResT  = std::tuple<std::string_view/*clientNonce*/, std::string_view/*client user name*/, std::string_view/*clientFirstWithoutHeader*/>;
    using ParseClientFinalResT  = std::tuple<std::string_view/*clientFinalMessageWithoutProof*/, std::string_view/*clientProof*/>;
    using ProofResT             = std::tuple<GpCryptoHash_Hmac::Res256T/*clientKey*/, GpCryptoHash_Hmac::Res256T/*serverKey*/, SmallContainerT/*authMessage*/,
                                             SmallContainerT/*clientFinalMessageWithoutProof*/, SmallContainerT/*clientProof*/>;

public:
                                    GpCryptoSASLScram           (HashTypeT          aHashType,
                                                                 KeyDerivationFnT   aKeyDerivationFn) noexcept;
                                    ~GpCryptoSASLScram          (void) noexcept;

    void                            Reset                       (void) noexcept;

    // Client side API
    SmallContainerT                 ClientFirstMessage          (GpSpanByteR aUserName);
    SmallContainerT                 ClientFinalMessage          (GpSpanByteR aServerFirstMessage,
                                                                 GpSpanByteR aPassword);
    void                            ValidateServerFinal         (GpSpanByteR aServerFinalMessage);

#if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)
    // Server side API
    SmallContainerT                 ServerFirstMessage          (GpSpanByteR aClientFirstMessage);
    SmallContainerT                 ServerFinalMessage          (GpSpanByteR aClientFinalMessage,
                                                                 GpSpanByteR aUserName,
                                                                 GpSpanByteR aPassword);
#endif// #if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)

private:
    static SmallContainerT          SGenerateNonce              (void);
    static ParseServerFirstResT     SParseServerFirstMessage    (GpSpanByteR    aServerFirstMessage,
                                                                 size_t         aClientNonceSize);
    static GpSpanByteR              SParseServerFinalMessage    (GpSpanByteR aServerFinalMessage);

#if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)
    static SmallContainerT          SGenerateSalt               (void);
    static ParseClientFirstResT     SParseClientFirstMessage    (GpSpanByteR aClientFirstMessage);
    static ParseClientFinalResT     SParseClientFinalMessage    (GpSpanByteR aClientFinalMessage);
#endif// #if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)

    static ProofResT                SMakeProof                  (GpSpanByteR    aClientNonce,
                                                                 GpSpanByteR    aServerNonce,
                                                                 GpSpanByteR    aClientFirstWithoutHeader,
                                                                 GpSpanByteR    aServerFirstMessage,
                                                                 GpSpanByteR    aServerSalt,
                                                                 size_t         aIterationsCount,
                                                                 GpSpanByteR    aPassword);

private:
    HashTypeT                       iHashType;
    KeyDerivationFnT                iKeyDerivationFn;

    SmallContainerT                 iClientUserName;
    SmallContainerT                 iClientNonce;
    SmallContainerT                 iServerNonce;
    SmallContainerT                 iServerSalt;
    SmallContainerT                 iClientFirstWithoutHeader;
    SmallContainerT                 iServerFirstMessage;
    size_t                          iIterationsCount    = 4096;

    GpCryptoHash_Hmac::Res256T      iClientKey;
    GpCryptoHash_Hmac::Res256T      iServerKey;
    SmallContainerT                 iAuthMessage;
};

}// namespace GPlatform
