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
    private int _finalized;
    private int _disposed;

    public IncrementalPoly1305(ReadOnlySpan<byte> oneTimeKey)
    {
        Sodium.Initialize();
        Reinitialize(oneTimeKey);
    }

    public unsafe void Reinitialize(ReadOnlySpan<byte> oneTimeKey)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        Validation.EqualTo($"{nameof(oneTimeKey)}.{nameof(oneTimeKey.Length)}", oneTimeKey.Length, KeySize);
        if (_state == null) {
            _state = NativeMemory.AlignedAlloc(crypto_onetimeauth_poly1305_statebytes, alignment: crypto_onetimeauth_poly1305_statebytes_CRYPTO_ALIGN);
        }
        int ret = crypto_onetimeauth_poly1305_init(_state, oneTimeKey);
        if (ret != 0) { throw new CryptographicException("Error initializing message authentication code state."); }
        Interlocked.Exchange(ref _finalized, 0);
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (Interlocked.CompareExchange(ref _finalized, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot update after finalizing without reinitializing."); }
        int ret = crypto_onetimeauth_poly1305_update(_state, message, (ulong)message.Length);
        if (ret != 0) { throw new CryptographicException("Error updating message authentication code state."); }
    }

    public unsafe void Finalize(Span<byte> tag)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (Interlocked.CompareExchange(ref _finalized, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualTo($"{nameof(tag)}.{nameof(tag.Length)}", tag.Length, TagSize);
        int ret = crypto_onetimeauth_poly1305_final(_state, tag);
        if (ret != 0) { throw new CryptographicException("Error finalizing message authentication code."); }
        Interlocked.Exchange(ref _finalized, 1);
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> tag)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (Interlocked.CompareExchange(ref _finalized, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualTo($"{nameof(tag)}.{nameof(tag.Length)}", tag.Length, TagSize);
        Span<byte> computedTag = stackalloc byte[TagSize];
        try {
            Finalize(computedTag);
            return ConstantTime.Equals(tag, computedTag);
        }
        finally {
            SecureMemory.ZeroMemory(computedTag);
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private unsafe void Dispose(bool disposing)
    {
        // If _disposed is 0, set to 1
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 0) != 0) { return; }
        if (_state != null) {
            SecureMemory.ZeroMemory(new Span<byte>(_state, crypto_onetimeauth_poly1305_statebytes));
            NativeMemory.AlignedFree(_state);
            _state = null;
        }
    }

    ~IncrementalPoly1305()
    {
        Dispose(false);
    }
}
