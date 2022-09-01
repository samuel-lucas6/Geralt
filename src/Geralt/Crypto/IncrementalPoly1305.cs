using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalPoly1305 : IDisposable
{
    private crypto_onetimeauth_state _state;
    
    public IncrementalPoly1305(ReadOnlySpan<byte> oneTimeKey)
    {
        Validation.EqualToSize(nameof(oneTimeKey), oneTimeKey.Length, Poly1305.KeySize);
        Sodium.Initialise();
        Initialize(oneTimeKey);
    }

    private unsafe void Initialize(ReadOnlySpan<byte> oneTimeKey)
    {
        fixed (byte* k = oneTimeKey)
        {
            int ret = crypto_onetimeauth_init(ref _state, k);
            if (ret != 0) { throw new CryptographicException("Error initialising message authentication code."); }
        }
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        fixed (byte* m = message)
        {
            int ret = crypto_onetimeauth_update(ref _state, m, (ulong)message.Length);
            if (ret != 0) { throw new CryptographicException("Error updating message authentication code."); }
        }
    }

    public unsafe void Finalize(Span<byte> tag)
    {
        Validation.EqualToSize(nameof(tag), tag.Length, Poly1305.TagSize);
        fixed (byte* t = tag)
        {
            int ret = crypto_onetimeauth_final(ref _state, t);
            if (ret != 0) { throw new CryptographicException("Error finalising message authentication code."); }
        }
    }
    
    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}