using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalEd25519ph : IDisposable
{
    public const int PublicKeySize = Ed25519.PublicKeySize;
    public const int PrivateKeySize = Ed25519.PrivateKeySize;
    public const int SignatureSize = Ed25519.SignatureSize;

    private crypto_sign_state _state;
    private bool _finalized;
    private bool _disposed;

    public IncrementalEd25519ph()
    {
        Sodium.Initialize();
        Reinitialize();
    }

    public void Reinitialize()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        _finalized = false;
        int ret = crypto_sign_init(ref _state);
        if (ret != 0) { throw new CryptographicException("Error initializing signature scheme state."); }
    }

    public void Update(ReadOnlySpan<byte> message)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        if (_finalized) { throw new InvalidOperationException("Cannot update after finalizing without reinitializing."); }
        int ret = crypto_sign_update(ref _state, message, (ulong)message.Length);
        if (ret != 0) { throw new CryptographicException("Error updating signature scheme state."); }
    }

    public void Finalize(Span<byte> signature, ReadOnlySpan<byte> privateKey)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        _finalized = true;
        int ret = crypto_sign_final_create(ref _state, signature, signatureLength: out _, privateKey);
        if (ret != 0) { throw new CryptographicException("Error finalizing signature."); }
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        _finalized = true;
        return crypto_sign_final_verify(ref _state, signature, publicKey) == 0;
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void Dispose()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
        _state = default;
        _disposed = true;
    }
}
