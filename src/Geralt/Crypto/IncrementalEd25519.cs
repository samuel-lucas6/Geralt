using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalEd25519 : IDisposable
{
    public const int PublicKeySize = Ed25519.PublicKeySize;
    public const int PrivateKeySize = Ed25519.PrivateKeySize;
    public const int SignatureSize = Ed25519.SignatureSize;
    public const int SeedSize = Ed25519.SeedSize;
    
    private crypto_sign_state _state;
    
    public IncrementalEd25519()
    {
        Sodium.Initialise();
        Initialize();
    }
    
    private void Initialize()
    {
        int ret = crypto_sign_init(ref _state);
        if (ret != 0) { throw new CryptographicException("Error initialising signature scheme."); }
    }
    
    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        fixed (byte* m = message)
        {
            int ret = crypto_sign_update(ref _state, m, (ulong)message.Length);
            if (ret != 0) { throw new CryptographicException("Error updating signature scheme."); }
        }
    }
    
    public unsafe void Finalize(Span<byte> signature, ReadOnlySpan<byte> privateKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        fixed (byte* s = signature, p = privateKey)
        {
            int ret = crypto_sign_final_create(ref _state, s, signatureLength: out _, p);
            if (ret != 0) { throw new CryptographicException("Error finalising signature."); }
        }
    }
    
    public unsafe bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        fixed (byte* s = signature, p = publicKey)
        {
            return crypto_sign_final_verify(ref _state, s, p) == 0;
        }
    }
    
    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}