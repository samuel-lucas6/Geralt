using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalEd25519ph : IDisposable
{
    public const int PublicKeySize = Ed25519.PublicKeySize;
    public const int PrivateKeySize = Ed25519.PrivateKeySize;
    public const int SignatureSize = Ed25519.SignatureSize;

    private unsafe void* _state;
    private int _finalized;
    private int _disposed;

    public unsafe IncrementalEd25519ph()
    {
        Sodium.Initialize();
        _state = NativeMemory.Alloc(crypto_sign_ed25519ph_statebytes);
        Reinitialize();
    }

    public unsafe void Reinitialize()
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        int ret = crypto_sign_ed25519ph_init(_state);
        if (ret != 0) { throw new CryptographicException("Error initializing signature scheme state."); }
        Interlocked.Exchange(ref _finalized, 0);
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        if (Interlocked.CompareExchange(ref _finalized, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot update after finalizing without reinitializing."); }
        int ret = crypto_sign_ed25519ph_update(_state, message, (ulong)message.Length);
        if (ret != 0) { throw new CryptographicException("Error updating signature scheme state."); }
    }

    public unsafe void Finalize(Span<byte> signature, ReadOnlySpan<byte> privateKey)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        if (Interlocked.CompareExchange(ref _finalized, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualTo($"{nameof(signature)}.{nameof(signature.Length)}", signature.Length, SignatureSize);
        Validation.EqualTo($"{nameof(privateKey)}.{nameof(privateKey.Length)}", privateKey.Length, PrivateKeySize);
        int ret = crypto_sign_ed25519ph_final_create(_state, signature, signatureLength: out _, privateKey);
        if (ret != 0) { throw new CryptographicException("Error finalizing signature."); }
        Interlocked.Exchange(ref _finalized, 1);
    }

    public unsafe bool FinalizeAndVerify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        if (Interlocked.CompareExchange(ref _finalized, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualTo($"{nameof(signature)}.{nameof(signature.Length)}", signature.Length, SignatureSize);
        Validation.EqualTo($"{nameof(publicKey)}.{nameof(publicKey.Length)}", publicKey.Length, PublicKeySize);
        int ret = crypto_sign_ed25519ph_final_verify(_state, signature, publicKey);
        Interlocked.Exchange(ref _finalized, 1);
        return ret == 0;
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
            SecureMemory.ZeroMemory(new Span<byte>(_state, crypto_sign_ed25519ph_statebytes));
            NativeMemory.Free(_state);
            _state = null;
        }
    }

    ~IncrementalEd25519ph()
    {
        Dispose(false);
    }
}
