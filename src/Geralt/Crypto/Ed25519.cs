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
        Sodium.Initialise();
        fixed (byte* p = publicKey, s = privateKey)
        {
            int ret = crypto_sign_keypair(p, s);
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
            int ret = crypto_sign_seed_keypair(pk, sk, s);
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
            int ret = crypto_sign_ed25519_sk_to_pk(p, s);
            if (ret != 0) { throw new CryptographicException("Unable to compute public key from private key."); }
        }
    }

    public static unsafe void GetX25519PublicKey(Span<byte> X25519PublicKey, ReadOnlySpan<byte> Ed25519PublicKey)
    {
        Validation.EqualToSize(nameof(X25519PublicKey), X25519PublicKey.Length, X25519.PublicKeySize);
        Validation.EqualToSize(nameof(Ed25519PublicKey), Ed25519PublicKey.Length, PublicKeySize);
        Sodium.Initialise();
        fixed (byte* x = X25519PublicKey, e = Ed25519PublicKey)
        {
            int ret = crypto_sign_ed25519_pk_to_curve25519(x, e);
            if (ret != 0) { throw new CryptographicException("Unable to compute X25519 public key."); }
        }
    }

    public static unsafe void GetX25519PrivateKey(Span<byte> X25519PrivateKey, ReadOnlySpan<byte> Ed25519PrivateKey)
    {
        Validation.EqualToSize(nameof(X25519PrivateKey), X25519PrivateKey.Length, X25519.PrivateKeySize);
        Validation.EqualToSize(nameof(Ed25519PrivateKey), Ed25519PrivateKey.Length, PrivateKeySize);
        Sodium.Initialise();
        fixed (byte* x = X25519PrivateKey, e = Ed25519PrivateKey)
        {
            int ret = crypto_sign_ed25519_sk_to_curve25519(x, e);
            if (ret != 0) { throw new CryptographicException("Unable to compute X25519 private key."); }
        }
    }

    public static unsafe void Sign(Span<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.NotEmpty(nameof(message), message.Length);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Sodium.Initialise();
        fixed (byte* s = signature, m = message, p = privateKey)
        {
            int ret = crypto_sign_detached(s, signatureLength: out _, m, (ulong)message.Length, p);
            if (ret != 0) { throw new CryptographicException("Unable to compute signature."); }
        }
    }

    public static unsafe bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.NotEmpty(nameof(message), message.Length);
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        Sodium.Initialise();
        fixed (byte* s = signature, m = message, p = publicKey)
            return crypto_sign_verify_detached(s, m, (ulong)message.Length, p) == 0;
    }
}