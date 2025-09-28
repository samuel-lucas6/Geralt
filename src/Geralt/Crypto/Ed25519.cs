using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class Ed25519
{
    public const int PublicKeySize = crypto_sign_PUBLICKEYBYTES;
    public const int PrivateKeySize = crypto_sign_SECRETKEYBYTES;
    public const int SignatureSize = crypto_sign_BYTES;
    public const int SeedSize = crypto_sign_SEEDBYTES;

    public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        int ret = crypto_sign_keypair(publicKey, privateKey);
        if (ret != 0) { throw new CryptographicException("Unable to generate key pair."); }
    }

    public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Validation.EqualToSize(nameof(seed), seed.Length, SeedSize);
        Sodium.Initialize();
        int ret = crypto_sign_seed_keypair(publicKey, privateKey, seed);
        if (ret != 0) { throw new CryptographicException("Unable to generate key pair from seed."); }
    }

    public static void GetPublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        int ret = crypto_sign_ed25519_sk_to_pk(publicKey, privateKey);
        if (ret != 0) { throw new CryptographicException("Unable to retrieve public key from private key."); }
    }

    public static void ComputeX25519PublicKey(Span<byte> x25519PublicKey, ReadOnlySpan<byte> ed25519PublicKey)
    {
        Validation.EqualToSize(nameof(x25519PublicKey), x25519PublicKey.Length, X25519.PublicKeySize);
        Validation.EqualToSize(nameof(ed25519PublicKey), ed25519PublicKey.Length, PublicKeySize);
        Sodium.Initialize();
        int ret = crypto_sign_ed25519_pk_to_curve25519(x25519PublicKey, ed25519PublicKey);
        if (ret != 0) { throw new CryptographicException("Unable to compute X25519 public key."); }
    }

    public static void ComputeX25519PrivateKey(Span<byte> x25519PrivateKey, ReadOnlySpan<byte> ed25519PrivateKey)
    {
        Validation.EqualToSize(nameof(x25519PrivateKey), x25519PrivateKey.Length, X25519.PrivateKeySize);
        Validation.EqualToSize(nameof(ed25519PrivateKey), ed25519PrivateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        int ret = crypto_sign_ed25519_sk_to_curve25519(x25519PrivateKey, ed25519PrivateKey);
        if (ret != 0) { throw new CryptographicException("Unable to compute X25519 private key."); }
    }

    public static void Sign(Span<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        int ret = crypto_sign_detached(signature, signatureLength: out _, message, (ulong)message.Length, privateKey);
        if (ret != 0) { throw new CryptographicException("Unable to compute signature."); }
    }

    public static bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Sodium.Initialize();
        return crypto_sign_verify_detached(signature, message, (ulong)message.Length, publicKey) == 0;
    }
}
