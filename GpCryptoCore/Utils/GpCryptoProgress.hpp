#pragma once

#include <GpCrypto/GpCryptoCore/GpCryptoCore_global.hpp>
#include <GpCore2/Config/GpConfig.hpp>
#include <GpCore2/GpUtils/Macro/GpMacroClass.hpp>
#include <GpCore2/GpUtils/EventBus/GpEventChannel.hpp>
#include <GpCore2/GpUtils/Types/Containers/GpAny.hpp>

namespace GPlatform {

class GP_CRYPTO_CORE_API GpCryptoProgress
{
    CLASS_REMOVE_CTRS_MOVE_COPY(GpCryptoProgress)

public:
    struct Event
    {
        double      iProgress       = 0.0;  // [0.0...100.0]
        u_int_64    iProgressSize   = 0;    // [0..iTotalSize]
        u_int_64    iTotalSize      = 0;
        s_int_64    iAttrCode       = -1;
    };

    using ChannelT = GpEventChannel<size_t, Event>;

public:
            GpCryptoProgress    (u_int_64   aTotalSize,
                                 double     aEmitDelta) noexcept;
            ~GpCryptoProgress   (void) noexcept = default;

    void    Update              (u_int_64   aProgressSize,
                                 s_int_64   aAttrCode,
                                 ChannelT&  aEventChannel);

private:
    const u_int_64  iTotalSize;
    const double    iEmitDelta;
    double          iProgress = 0.0;    // used for emit delta
};

}// namespace GPlatform
