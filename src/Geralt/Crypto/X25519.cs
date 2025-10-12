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

    public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        int ret = crypto_kx_keypair(publicKey, privateKey);
        if (ret != 0) { throw new CryptographicException("Unable to generate key pair."); }
    }

    public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(seed), seed.Length, SeedSize);
        Sodium.Initialize();
        int ret = crypto_kx_seed_keypair(publicKey, privateKey, seed);
        if (ret != 0) { throw new CryptographicException("Unable to generate key pair from seed."); }
    }

    public static void ComputePublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        int ret = crypto_scalarmult_base(publicKey, privateKey);
        if (ret != 0) { throw new CryptographicException("Unable to compute public key from private key."); }
    }

    public static void ComputeSharedSecret(Span<byte> sharedSecret, ReadOnlySpan<byte> senderPrivateKey, ReadOnlySpan<byte> recipientPublicKey)
    {
        Validation.EqualToSize(nameof(sharedSecret), sharedSecret.Length, SharedSecretSize);
        Validation.EqualToSize(nameof(senderPrivateKey), senderPrivateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(recipientPublicKey), recipientPublicKey.Length, PublicKeySize);
        Sodium.Initialize();
        int ret = crypto_scalarmult(sharedSecret, senderPrivateKey, recipientPublicKey);
        if (ret != 0) { throw new CryptographicException("Invalid public key."); }
    }

    public static void DeriveSenderSharedKey(Span<byte> sharedKey, ReadOnlySpan<byte> senderPrivateKey, ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> preSharedKey = default)
    {
        Validation.EqualToSize(nameof(sharedKey), sharedKey.Length, SharedKeySize);
        Validation.EqualToSize(nameof(senderPrivateKey), senderPrivateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(recipientPublicKey), recipientPublicKey.Length, PublicKeySize);
        if (preSharedKey.Length != 0) { Validation.SizeBetween(nameof(preSharedKey), preSharedKey.Length, MinPreSharedKeySize, MaxPreSharedKeySize); }
        DeriveSharedKey(sharedKey, senderPrivateKey, recipientPublicKey, preSharedKey, isSender: true);
    }

    public static void DeriveRecipientSharedKey(Span<byte> sharedKey, ReadOnlySpan<byte> recipientPrivateKey, ReadOnlySpan<byte> senderPublicKey, ReadOnlySpan<byte> preSharedKey = default)
    {
        Validation.EqualToSize(nameof(sharedKey), sharedKey.Length, SharedKeySize);
        Validation.EqualToSize(nameof(recipientPrivateKey), recipientPrivateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(senderPublicKey), senderPublicKey.Length, PublicKeySize);
        if (preSharedKey.Length != 0) { Validation.SizeBetween(nameof(preSharedKey), preSharedKey.Length, MinPreSharedKeySize, MaxPreSharedKeySize); }
        DeriveSharedKey(sharedKey, recipientPrivateKey, senderPublicKey, preSharedKey, isSender: false);
    }

    private static void DeriveSharedKey(Span<byte> sharedKey, ReadOnlySpan<byte> yourPrivateKey, ReadOnlySpan<byte> othersPublicKey, ReadOnlySpan<byte> preSharedKey, bool isSender)
    {
        Span<byte> sharedSecret = stackalloc byte[SharedSecretSize];
        ComputeSharedSecret(sharedSecret, yourPrivateKey, othersPublicKey);
        Span<byte> yourPublicKey = stackalloc byte[PublicKeySize];
        ComputePublicKey(yourPublicKey, yourPrivateKey);
        using var blake2b = new IncrementalBLAKE2b(sharedKey.Length, preSharedKey);
        blake2b.Update(sharedSecret);
        blake2b.Update(isSender ? yourPublicKey : othersPublicKey);
        blake2b.Update(isSender ? othersPublicKey : yourPublicKey);
        blake2b.Finalize(sharedKey);
        SecureMemory.ZeroMemory(sharedSecret);
        SecureMemory.ZeroMemory(yourPublicKey);
    }
}
