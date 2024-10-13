#include <GpCrypto/GpCryptoUtilsWasm/SASL/Scram/GpCryptoSASLScramWasm.hpp>

namespace GPlatform {

GpCryptoSASLScramWasm::GpCryptoSASLScramWasm (void) noexcept
{
}

GpCryptoSASLScramWasm::GpCryptoSASLScramWasm (GpCryptoSASLScram::SP aCryptoSASLScramSP) noexcept:
iCryptoSASLScramSP{std::move(aCryptoSASLScramSP)}
{
}

GpCryptoSASLScramWasm::~GpCryptoSASLScramWasm (void) noexcept
{
}

void    GpCryptoSASLScramWasm::reset (void)
{
    WasmEmscriptenExceptionCatcherVoid
    (
        [&]()
        {
            iCryptoSASLScramSP.Vn().Reset();
        }
    );
}

emscripten::val GpCryptoSASLScramWasm::client_first_message (const std::string& aUserName)
{
    return WasmEmscriptenExceptionCatcher
    (
        [&]()
        {
            const auto msg = iCryptoSASLScramSP.Vn().ClientFirstMessage(aUserName);

            return emscripten::val
            {
                std::string
                (
                    GpSpanByteR{msg}.AsStringView()
                )
            };
        }
    );
}

emscripten::val GpCryptoSASLScramWasm::client_final_message
(
    const std::string& aServerFirstMessage,
    const std::string& aPassword
)
{
    return WasmEmscriptenExceptionCatcher
    (
        [&]()
        {
            const auto msg = iCryptoSASLScramSP.Vn().ClientFinalMessage
            (
                aServerFirstMessage,
                aPassword
            );

            return emscripten::val
            {
                std::string
                (
                    GpSpanByteR{msg}.AsStringView()
                )
            };
        }
    );
}

emscripten::val GpCryptoSASLScramWasm::validate_server_final (const std::string& aServerFinalMessage)
{
    return WasmEmscriptenExceptionCatcher
    (
        [&]()
        {
            bool res = true;

            try
            {
                iCryptoSASLScramSP.Vn().ValidateServerFinal(aServerFinalMessage);
            } catch (const std::exception& ex)
            {
                res = false;
            }

            return emscripten::val{res};
        }
    );
}

#if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)

emscripten::val GpCryptoSASLScramWasm::server_first_message (const std::string& aClientFirstMessage)
{
    return WasmEmscriptenExceptionCatcher
    (
        [&]()
        {
            const auto msg = iCryptoSASLScramSP.Vn().ServerFirstMessage(aClientFirstMessage);

            return emscripten::val
            {
                std::string
                (
                    GpSpanByteR{msg}.AsStringView()
                )
            };
        }
    );
}

emscripten::val GpCryptoSASLScramWasm::server_final_message
(
    const std::string& aClientFinalMessage,
    const std::string& aUserName,
    const std::string& aPassword
)
{
    return WasmEmscriptenExceptionCatcher
    (
        [&]()
        {
            const auto msg = iCryptoSASLScramSP.Vn().ServerFinalMessage
            (
                aClientFinalMessage,
                aUserName,
                aPassword
            );

            return emscripten::val
            {
                std::string
                (
                    GpSpanByteR{msg}.AsStringView()
                )
            };
        }
    );
}

#endif// #if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)

emscripten::val GpCryptoSASLScramWasm::new_instance (void)
{
    return WasmEmscriptenExceptionCatcher
    (
        [&]()
        {
            GpCryptoSASLScram::SP           cryptoSASLScramSP   = MakeSP<GpCryptoSASLScram>(GpCryptoSASLScram::HashTypeT::SHA_256, GpCryptoSASLScram::KeyDerivationFnT::PBKDF2);
            GpCryptoSASLScramWasm::STDSP    cryptoSASLScramWasm = std::make_shared<GpCryptoSASLScramWasm>(std::move(cryptoSASLScramSP));

            return emscripten::val{cryptoSASLScramWasm};
        }
    );
}

}// namespace GPlatform

EMSCRIPTEN_BINDINGS(GpCryptoSASLScramWasm_bind)
{
    emscripten::class_<GPlatform::GpCryptoSASLScramWasm>("GpCryptoSASLScram")
        .smart_ptr_constructor("GpCryptoSASLScram", &std::make_shared<GPlatform::GpCryptoSASLScramWasm>)
        .function("reset", &GPlatform::GpCryptoSASLScramWasm::reset)
        .function("client_first_message", &GPlatform::GpCryptoSASLScramWasm::client_first_message)
        .function("client_final_message", &GPlatform::GpCryptoSASLScramWasm::client_final_message)
        .function("validate_server_final", &GPlatform::GpCryptoSASLScramWasm::validate_server_final)
#if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)
        .function("server_first_message", &GPlatform::GpCryptoSASLScramWasm::server_first_message)
        .function("server_final_message", &GPlatform::GpCryptoSASLScramWasm::server_final_message)
#endif// #if defined(GP_CRYPTO_USE_SASL_SCRAM_SERVER_AUTH)
        .class_function("new_instance", &GPlatform::GpCryptoSASLScramWasm::new_instance)
    ;
};
