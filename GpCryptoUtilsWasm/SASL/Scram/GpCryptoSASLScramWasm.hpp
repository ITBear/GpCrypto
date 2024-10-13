#pragma once

#include <GpCrypto/GpCryptoUtilsWasm/GpCryptoUtilsWasm_global.hpp>
#include <GpCrypto/GpCryptoUtils/SASL/Scram/GpCryptoSASLScram.hpp>

namespace GPlatform {

class GpCryptoSASLScramWasm
{
public:
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoSASLScramWasm)

    using STDSP = std::shared_ptr<GpCryptoSASLScramWasm>;

public:
                                GpCryptoSASLScramWasm   (void) noexcept;
                                GpCryptoSASLScramWasm   (GpCryptoSASLScram::SP aCryptoSASLScramSP) noexcept;
                                ~GpCryptoSASLScramWasm  (void) noexcept;

    void                        reset                   (void);

    // Client API
    emscripten::val             client_first_message    (const std::string& aUserName);
    emscripten::val             client_final_message    (const std::string& aServerFirstMessage,
                                                         const std::string& aPassword);
    emscripten::val             validate_server_final   (const std::string& aServerFinalMessage);

#if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)
    // Server side API
    emscripten::val             server_first_message    (const std::string& aClientFirstMessage);
    emscripten::val             server_final_message    (const std::string& aClientFinalMessage,
                                                         const std::string& aUserName,
                                                         const std::string& aPassword);
#endif// #if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)

    static emscripten::val      new_instance            (void);

private:
    GpCryptoSASLScram::SP       iCryptoSASLScramSP;
};

}// namespace GPlatform
