using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalPoly1305 : IDisposable
{
    public const int KeySize = Poly1305.KeySize;
    public const int TagSize = Poly1305.TagSize;
    public const int BlockSize = Poly1305.BlockSize;

    private unsafe void* _state;
    private bool _finalized;
    private bool _disposed;

    public unsafe IncrementalPoly1305(ReadOnlySpan<byte> oneTimeKey)
    {
        Sodium.Initialize();
        _state = NativeMemory.AlignedAlloc(crypto_onetimeauth_poly1305_statebytes, alignment: crypto_onetimeauth_poly1305_statebytes_CRYPTO_ALIGN);
        Reinitialize(oneTimeKey);
    }

    public unsafe void Reinitialize(ReadOnlySpan<byte> oneTimeKey)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        Validation.EqualTo($"{nameof(oneTimeKey)}.{nameof(oneTimeKey.Length)}", oneTimeKey.Length, KeySize);
        int ret = crypto_onetimeauth_poly1305_init(_state, oneTimeKey);
        if (ret != 0) { throw new CryptographicException("Error initializing message authentication code state."); }
        _finalized = false;
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (_finalized) { throw new InvalidOperationException("Cannot update after finalizing without reinitializing."); }
        int ret = crypto_onetimeauth_poly1305_update(_state, message, (ulong)message.Length);
        if (ret != 0) { throw new CryptographicException("Error updating message authentication code state."); }
    }

    public unsafe void Finalize(Span<byte> tag)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualTo($"{nameof(tag)}.{nameof(tag.Length)}", tag.Length, TagSize);
        int ret = crypto_onetimeauth_poly1305_final(_state, tag);
        if (ret != 0) { throw new CryptographicException("Error finalizing message authentication code."); }
        _finalized = true;
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> tag)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualTo($"{nameof(tag)}.{nameof(tag.Length)}", tag.Length, TagSize);
        Span<byte> computedTag = stackalloc byte[TagSize];
        Finalize(computedTag);
        bool equal = ConstantTime.Equals(tag, computedTag);
        SecureMemory.ZeroMemory(computedTag);
        return equal;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private unsafe void Dispose(bool disposing)
    {
        if (_disposed) { return; }
        if (_state != null) {
            SecureMemory.ZeroMemory(new Span<byte>(_state, crypto_onetimeauth_poly1305_statebytes));
            NativeMemory.AlignedFree(_state);
            _state = null;
        }
        _disposed = true;
    }

    ~IncrementalPoly1305()
    {
        Dispose(false);
    }
}
