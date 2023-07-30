using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class Ed25519
{
    public const int PublicKeySize = crypto_sign_PUBLICKEYBYTES;
    public const int PrivateKeySize = crypto_sign_SECRETKEYBYTES;
    public const int SignatureSize = crypto_sign_BYTES;
    public const int SeedSize = crypto_sign_SEEDBYTES;

    public static unsafe void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        fixed (byte* pk = publicKey, sk = privateKey)
        {
            int ret = crypto_sign_keypair(pk, sk);
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
            int ret = crypto_sign_seed_keypair(pk, sk, s);
            if (ret != 0) { throw new CryptographicException("Unable to generate key pair from seed."); }
        }
    }

    public static unsafe void ComputePublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        fixed (byte* pk = publicKey, sk = privateKey)
        {
            int ret = crypto_sign_ed25519_sk_to_pk(pk, sk);
            if (ret != 0) { throw new CryptographicException("Unable to compute public key from private key."); }
        }
    }

    public static unsafe void GetX25519PublicKey(Span<byte> x25519PublicKey, ReadOnlySpan<byte> ed25519PublicKey)
    {
        Validation.EqualToSize(nameof(x25519PublicKey), x25519PublicKey.Length, X25519.PublicKeySize);
        Validation.EqualToSize(nameof(ed25519PublicKey), ed25519PublicKey.Length, PublicKeySize);
        Sodium.Initialize();
        fixed (byte* x = x25519PublicKey, e = ed25519PublicKey)
        {
            int ret = crypto_sign_ed25519_pk_to_curve25519(x, e);
            if (ret != 0) { throw new CryptographicException("Unable to compute X25519 public key."); }
        }
    }

    public static unsafe void GetX25519PrivateKey(Span<byte> x25519PrivateKey, ReadOnlySpan<byte> ed25519PrivateKey)
    {
        Validation.EqualToSize(nameof(x25519PrivateKey), x25519PrivateKey.Length, X25519.PrivateKeySize);
        Validation.EqualToSize(nameof(ed25519PrivateKey), ed25519PrivateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        fixed (byte* x = x25519PrivateKey, e = ed25519PrivateKey)
        {
            int ret = crypto_sign_ed25519_sk_to_curve25519(x, e);
            if (ret != 0) { throw new CryptographicException("Unable to compute X25519 private key."); }
        }
    }

    public static unsafe void Sign(Span<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        fixed (byte* s = signature, m = message, sk = privateKey)
        {
            int ret = crypto_sign_detached(s, signatureLength: out _, m, (ulong)message.Length, sk);
            if (ret != 0) { throw new CryptographicException("Unable to compute signature."); }
        }
    }

    public static unsafe bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Sodium.Initialize();
        fixed (byte* s = signature, m = message, pk = publicKey)
            return crypto_sign_verify_detached(s, m, (ulong)message.Length, pk) == 0;
    }
}
