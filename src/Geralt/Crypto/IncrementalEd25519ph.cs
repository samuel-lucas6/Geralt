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

    public IncrementalEd25519ph()
    {
        Sodium.Initialize();
        Reinitialize();
    }

    public void Reinitialize()
    {
        _finalized = false;
        int ret = crypto_sign_init(ref _state);
        if (ret != 0) { throw new CryptographicException("Error initializing signature scheme state."); }
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        if (_finalized) { throw new InvalidOperationException("Cannot update after finalizing."); }
        fixed (byte* m = message)
        {
            int ret = crypto_sign_update(ref _state, m, (ulong)message.Length);
            if (ret != 0) { throw new CryptographicException("Error updating signature scheme state."); }
        }
    }

    public unsafe void Finalize(Span<byte> signature, ReadOnlySpan<byte> privateKey)
    {
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice."); }
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        _finalized = true;
        fixed (byte* s = signature, sk = privateKey)
        {
            int ret = crypto_sign_final_create(ref _state, s, signatureLength: out _, sk);
            if (ret != 0) { throw new CryptographicException("Error finalizing signature."); }
        }
    }

    public unsafe bool FinalizeAndVerify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice."); }
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        _finalized = true;
        fixed (byte* s = signature, pk = publicKey)
        {
            return crypto_sign_final_verify(ref _state, s, pk) == 0;
        }
    }

    public void Dispose()
    {
    }
}
