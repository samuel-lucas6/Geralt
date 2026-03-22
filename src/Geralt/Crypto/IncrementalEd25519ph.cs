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

    private crypto_sign_ed25519ph_state _state;
    private GCHandle _stateHandle;
    private bool _finalized;
    private bool _disposed;

    public IncrementalEd25519ph()
    {
        Sodium.Initialize();
        _stateHandle = GCHandle.Alloc(_state,  GCHandleType.Pinned);
        Reinitialize();
    }

    public void Reinitialize()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        int ret = crypto_sign_ed25519ph_init(ref _state);
        if (ret != 0) { throw new CryptographicException("Error initializing signature scheme state."); }
        _finalized = false;
    }

    public void Update(ReadOnlySpan<byte> message)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        if (_finalized) { throw new InvalidOperationException("Cannot update after finalizing without reinitializing."); }
        int ret = crypto_sign_ed25519ph_update(ref _state, message, (ulong)message.Length);
        if (ret != 0) { throw new CryptographicException("Error updating signature scheme state."); }
    }

    public void Finalize(Span<byte> signature, ReadOnlySpan<byte> privateKey)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualTo($"{nameof(signature)}.{nameof(signature.Length)}", signature.Length, SignatureSize);
        Validation.EqualTo($"{nameof(privateKey)}.{nameof(privateKey.Length)}", privateKey.Length, PrivateKeySize);
        int ret = crypto_sign_ed25519ph_final_create(ref _state, signature, signatureLength: out _, privateKey);
        if (ret != 0) { throw new CryptographicException("Error finalizing signature."); }
        _finalized = true;
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualTo($"{nameof(signature)}.{nameof(signature.Length)}", signature.Length, SignatureSize);
        Validation.EqualTo($"{nameof(publicKey)}.{nameof(publicKey.Length)}", publicKey.Length, PublicKeySize);
        _finalized = true;
        return crypto_sign_ed25519ph_final_verify(ref _state, signature, publicKey) == 0;
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
        fixed (void* s = &_state) {
            SecureMemory.ZeroMemory(new Span<byte>(s, Marshal.SizeOf(_state)));
        }
        if (_stateHandle.IsAllocated) { _stateHandle.Free(); }
        _disposed = true;
    }

    ~IncrementalEd25519ph()
    {
        Dispose(false);
    }
}
