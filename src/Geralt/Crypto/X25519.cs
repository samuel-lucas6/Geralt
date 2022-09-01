using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class X25519
{
    public const int PublicKeySize = crypto_kx_PUBLICKEYBYTES;
    public const int PrivateKeySize = crypto_kx_SECRETKEYBYTES;
    public const int SeedSize = crypto_kx_SEEDBYTES;
    public const int SharedSecretSize = crypto_kx_SESSIONKEYBYTES;
    public const int PreSharedKeySize = BLAKE2b.KeySize;
    public const int MinPreSharedKeySize = BLAKE2b.KeySize;
    public const int MaxPreSharedKeySize = BLAKE2b.MaxKeySize;

    public static unsafe void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialise();
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
        Sodium.Initialise();
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
        Sodium.Initialise();
        fixed (byte* p = publicKey, s = privateKey)
        {
            int ret = crypto_scalarmult_base(p, s);
            if (ret != 0) { throw new CryptographicException("Unable to compute public key from private key."); }
        }
    }

    public static unsafe void DeriveSenderSharedSecret(Span<byte> sharedSecret, ReadOnlySpan<byte> senderPrivateKey, ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> preSharedKey = default)
    {
        Validation.EqualToSize(nameof(sharedSecret), sharedSecret.Length, SharedSecretSize);
        Validation.EqualToSize(nameof(senderPrivateKey), senderPrivateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(recipientPublicKey), recipientPublicKey.Length, PublicKeySize);
        if (preSharedKey != default) { Validation.SizeBetween(nameof(preSharedKey), preSharedKey.Length, MinPreSharedKeySize, MaxPreSharedKeySize); }
        Span<byte> xCoordinate = stackalloc byte[SharedSecretSize];
        ComputeXCoordinate(xCoordinate, senderPrivateKey, recipientPublicKey);
        Span<byte> senderPublicKey = stackalloc byte[PublicKeySize];
        ComputePublicKey(senderPublicKey, senderPrivateKey);
        using var blake2b = new IncrementalBLAKE2b(sharedSecret.Length, preSharedKey);
        blake2b.Update(xCoordinate);
        blake2b.Update(senderPublicKey);
        blake2b.Update(recipientPublicKey);
        blake2b.Finalize(sharedSecret);
        CryptographicOperations.ZeroMemory(xCoordinate);
    }
    
    public static unsafe void DeriveRecipientSharedSecret(Span<byte> sharedSecret, ReadOnlySpan<byte> recipientPrivateKey, ReadOnlySpan<byte> senderPublicKey, ReadOnlySpan<byte> preSharedKey = default)
    {
        Validation.EqualToSize(nameof(sharedSecret), sharedSecret.Length, SharedSecretSize);
        Validation.EqualToSize(nameof(recipientPrivateKey), recipientPrivateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(senderPublicKey), senderPublicKey.Length, PublicKeySize);
        if (preSharedKey != default) { Validation.SizeBetween(nameof(preSharedKey), preSharedKey.Length, MinPreSharedKeySize, MaxPreSharedKeySize); }
        Span<byte> xCoordinate = stackalloc byte[SharedSecretSize];
        ComputeXCoordinate(xCoordinate, recipientPrivateKey, senderPublicKey);
        Span<byte> recipientPublicKey = stackalloc byte[PublicKeySize];
        ComputePublicKey(recipientPublicKey, recipientPrivateKey);
        using var blake2b = new IncrementalBLAKE2b(sharedSecret.Length, preSharedKey);
        blake2b.Update(xCoordinate);
        blake2b.Update(senderPublicKey);
        blake2b.Update(recipientPublicKey);
        blake2b.Finalize(sharedSecret);
        CryptographicOperations.ZeroMemory(xCoordinate);
    }
    
    public static unsafe void ComputeXCoordinate(Span<byte> xCoordinate, ReadOnlySpan<byte> senderPrivateKey, ReadOnlySpan<byte> recipientPublicKey)
    {
        Validation.EqualToSize(nameof(xCoordinate), xCoordinate.Length, SharedSecretSize);
        Validation.EqualToSize(nameof(senderPrivateKey), senderPrivateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(recipientPublicKey), recipientPublicKey.Length, PublicKeySize);
        Sodium.Initialise();
        fixed (byte* x = xCoordinate, s = senderPrivateKey, p = recipientPublicKey)
        {
            int ret = crypto_scalarmult(x, s, p);
            if (ret != 0) { throw new CryptographicException("Invalid public key."); }
        }
    }
}