using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class X25519
{
    public const int PublicKeySize = crypto_kx_PUBLICKEYBYTES;
    public const int PrivateKeySize = crypto_kx_SECRETKEYBYTES;
    public const int SeedSize = crypto_kx_SEEDBYTES;
    public const int SharedSecretSize = crypto_scalarmult_BYTES;
    public const int SharedKeySize = crypto_kx_SESSIONKEYBYTES;
    public const int PreSharedKeySize = BLAKE2b.KeySize;
    public const int MinPreSharedKeySize = BLAKE2b.MinKeySize;
    public const int MaxPreSharedKeySize = BLAKE2b.MaxKeySize;

    public static unsafe void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        fixed (byte* p = publicKey, s = privateKey)
        {
            int ret = crypto_kx_keypair(p, s);
            if (ret != 0) { throw new CryptographicException("Unable to generate key pair."); }
        }
    }
    
    public static unsafe void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(seed), seed.Length, SeedSize);
        Sodium.Initialize();
        fixed (byte* pk = publicKey, sk = privateKey, s = seed)
        {
            int ret = crypto_kx_seed_keypair(pk, sk, s);
            if (ret != 0) { throw new CryptographicException("Unable to generate key pair from seed."); }
        }
    }

    public static unsafe void ComputePublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        fixed (byte* p = publicKey, s = privateKey)
        {
            int ret = crypto_scalarmult_base(p, s);
            if (ret != 0) { throw new CryptographicException("Unable to compute public key from private key."); }
        }
    }

    public static unsafe void DeriveSenderSharedKey(Span<byte> sharedKey, ReadOnlySpan<byte> senderPrivateKey, ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> preSharedKey = default)
    {
        Validation.EqualToSize(nameof(sharedKey), sharedKey.Length, SharedKeySize);
        Validation.EqualToSize(nameof(senderPrivateKey), senderPrivateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(recipientPublicKey), recipientPublicKey.Length, PublicKeySize);
        if (preSharedKey != default) { Validation.SizeBetween(nameof(preSharedKey), preSharedKey.Length, MinPreSharedKeySize, MaxPreSharedKeySize); }
        Span<byte> sharedSecret = stackalloc byte[SharedSecretSize];
        ComputeSharedSecret(sharedSecret, senderPrivateKey, recipientPublicKey);
        Span<byte> senderPublicKey = stackalloc byte[PublicKeySize];
        ComputePublicKey(senderPublicKey, senderPrivateKey);
        using var blake2b = new IncrementalBLAKE2b(sharedKey.Length, preSharedKey);
        blake2b.Update(sharedSecret);
        blake2b.Update(senderPublicKey);
        blake2b.Update(recipientPublicKey);
        blake2b.Finalize(sharedKey);
        CryptographicOperations.ZeroMemory(sharedSecret);
    }
    
    public static unsafe void DeriveRecipientSharedKey(Span<byte> sharedKey, ReadOnlySpan<byte> recipientPrivateKey, ReadOnlySpan<byte> senderPublicKey, ReadOnlySpan<byte> preSharedKey = default)
    {
        Validation.EqualToSize(nameof(sharedKey), sharedKey.Length, SharedKeySize);
        Validation.EqualToSize(nameof(recipientPrivateKey), recipientPrivateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(senderPublicKey), senderPublicKey.Length, PublicKeySize);
        if (preSharedKey != default) { Validation.SizeBetween(nameof(preSharedKey), preSharedKey.Length, MinPreSharedKeySize, MaxPreSharedKeySize); }
        Span<byte> sharedSecret = stackalloc byte[SharedSecretSize];
        ComputeSharedSecret(sharedSecret, recipientPrivateKey, senderPublicKey);
        Span<byte> recipientPublicKey = stackalloc byte[PublicKeySize];
        ComputePublicKey(recipientPublicKey, recipientPrivateKey);
        using var blake2b = new IncrementalBLAKE2b(sharedKey.Length, preSharedKey);
        blake2b.Update(sharedSecret);
        blake2b.Update(senderPublicKey);
        blake2b.Update(recipientPublicKey);
        blake2b.Finalize(sharedKey);
        CryptographicOperations.ZeroMemory(sharedSecret);
    }
    
    public static unsafe void ComputeSharedSecret(Span<byte> sharedSecret, ReadOnlySpan<byte> senderPrivateKey, ReadOnlySpan<byte> recipientPublicKey)
    {
        Validation.EqualToSize(nameof(sharedSecret), sharedSecret.Length, SharedSecretSize);
        Validation.EqualToSize(nameof(senderPrivateKey), senderPrivateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(recipientPublicKey), recipientPublicKey.Length, PublicKeySize);
        Sodium.Initialize();
        fixed (byte* x = sharedSecret, s = senderPrivateKey, p = recipientPublicKey)
        {
            int ret = crypto_scalarmult(x, s, p);
            if (ret != 0) { throw new CryptographicException("Invalid public key."); }
        }
    }
}