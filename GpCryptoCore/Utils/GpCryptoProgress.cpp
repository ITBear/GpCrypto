#include <GpCrypto/GpCryptoCore/Utils/GpCryptoProgress.hpp>

namespace GPlatform {

GpCryptoProgress::GpCryptoProgress
(
    const u_int_64  aTotalSize,
    const double    aEmitDelta
) noexcept:
iTotalSize{aTotalSize},
iEmitDelta{aEmitDelta}
{
}

void    GpCryptoProgress::Update
(
    const u_int_64  aProgressSize,
    s_int_64        aAttrCode,
    ChannelT&       aEventChannel
)
{
    const double progress   = (double(aProgressSize) / double(iTotalSize)) * 100.0;
    const double delta      = iProgress - progress;

    if (   (delta >= iEmitDelta)
        || (progress >= 100.0))[[unlikely]]
    {
        iProgress = progress;

        aEventChannel.PushEvent
        (
            Event
            {
                .iProgress      = iProgress,
                .iProgressSize  = aProgressSize,
                .iTotalSize     = iTotalSize,
                .iAttrCode      = aAttrCode
            }
        );
    }
}

}// namespace GPlatform
