#pragma once

#include <GpCore2/GpUtils/Macro/GpMacroImportExport.hpp>

#if defined(GP_CRYPTO_CORE_LIBRARY)
    #define GP_CRYPTO_CORE_API GP_DECL_EXPORT
#else
    #define GP_CRYPTO_CORE_API GP_DECL_IMPORT
#endif

namespace GPlatform {}
