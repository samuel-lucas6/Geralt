using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalPoly1305 : IDisposable
{
    public const int KeySize = Poly1305.KeySize;
    public const int TagSize = Poly1305.TagSize;

    private crypto_onetimeauth_state _state;
    private bool _finalized;

    public IncrementalPoly1305(ReadOnlySpan<byte> oneTimeKey)
    {
        Validation.EqualToSize(nameof(oneTimeKey), oneTimeKey.Length, KeySize);
        Sodium.Initialize();
        _finalized = false;
        Initialize(oneTimeKey);
    }

    private unsafe void Initialize(ReadOnlySpan<byte> oneTimeKey)
    {
        fixed (byte* k = oneTimeKey)
        {
            int ret = crypto_onetimeauth_init(ref _state, k);
            if (ret != 0) { throw new CryptographicException("Error initializing message authentication code state."); }
        }
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        if (_finalized) { throw new InvalidOperationException("Cannot update after finalizing."); }
        fixed (byte* m = message)
        {
            int ret = crypto_onetimeauth_update(ref _state, m, (ulong)message.Length);
            if (ret != 0) { throw new CryptographicException("Error updating message authentication code state."); }
        }
    }

    public unsafe void Finalize(Span<byte> tag)
    {
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice."); }
        Validation.EqualToSize(nameof(tag), tag.Length, TagSize);
        _finalized = true;
        fixed (byte* t = tag)
        {
            int ret = crypto_onetimeauth_final(ref _state, t);
            if (ret != 0) { throw new CryptographicException("Error finalizing message authentication code."); }
        }
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> tag)
    {
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice."); }
        Validation.EqualToSize(nameof(tag), tag.Length, TagSize);
        Span<byte> computedTag = stackalloc byte[TagSize];
        Finalize(computedTag);
        bool equal = ConstantTime.Equals(tag, computedTag);
        CryptographicOperations.ZeroMemory(computedTag);
        return equal;
    }

    public void Dispose()
    {
    }
}
