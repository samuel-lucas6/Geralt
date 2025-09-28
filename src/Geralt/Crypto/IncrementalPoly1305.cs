using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalPoly1305 : IDisposable
{
    public const int KeySize = Poly1305.KeySize;
    public const int TagSize = Poly1305.TagSize;
    public const int BlockSize = Poly1305.BlockSize;

    private crypto_onetimeauth_state _state;
    private bool _finalized;
    private bool _disposed;

    public IncrementalPoly1305(ReadOnlySpan<byte> oneTimeKey)
    {
        Sodium.Initialize();
        Reinitialize(oneTimeKey);
    }

    public void Reinitialize(ReadOnlySpan<byte> oneTimeKey)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        Validation.EqualToSize(nameof(oneTimeKey), oneTimeKey.Length, KeySize);
        int ret = crypto_onetimeauth_init(ref _state, oneTimeKey);
        if (ret != 0) { throw new CryptographicException("Error initializing message authentication code state."); }
        _finalized = false;
    }

    public void Update(ReadOnlySpan<byte> message)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (_finalized) { throw new InvalidOperationException("Cannot update after finalizing without reinitializing."); }
        int ret = crypto_onetimeauth_update(ref _state, message, (ulong)message.Length);
        if (ret != 0) { throw new CryptographicException("Error updating message authentication code state."); }
    }

    public void Finalize(Span<byte> tag)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualToSize(nameof(tag), tag.Length, TagSize);
        int ret = crypto_onetimeauth_final(ref _state, tag);
        if (ret != 0) { throw new CryptographicException("Error finalizing message authentication code."); }
        _finalized = true;
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> tag)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualToSize(nameof(tag), tag.Length, TagSize);
        Span<byte> computedTag = stackalloc byte[TagSize];
        Finalize(computedTag);
        bool equal = ConstantTime.Equals(tag, computedTag);
        SecureMemory.ZeroMemory(computedTag);
        return equal;
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void Dispose()
    {
        if (_disposed) { return; }
        _state = default;
        _disposed = true;
    }
}
