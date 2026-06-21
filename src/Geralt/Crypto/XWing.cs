using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class XWing
{
    public const int PublicKeySize = crypto_kem_xwing_PUBLICKEYBYTES;
    public const int PrivateKeySize = crypto_kem_xwing_SECRETKEYBYTES;
    public const int SeedSize = crypto_kem_xwing_SEEDBYTES;
    public const int SharedSecretSize = crypto_kem_xwing_SHAREDSECRETBYTES;
    public const int CiphertextSize = crypto_kem_xwing_CIPHERTEXTBYTES;

    public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey)
    {
        Validation.EqualTo($"{nameof(publicKey)}.{nameof(publicKey.Length)}", publicKey.Length, PublicKeySize);
        Validation.EqualTo($"{nameof(privateKey)}.{nameof(privateKey.Length)}", privateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        int ret = crypto_kem_xwing_keypair(publicKey, privateKey);
        if (ret != 0) { throw new CryptographicException("Error generating key pair."); }
    }

    public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed)
    {
        Validation.EqualTo($"{nameof(publicKey)}.{nameof(publicKey.Length)}", publicKey.Length, PublicKeySize);
        Validation.EqualTo($"{nameof(privateKey)}.{nameof(privateKey.Length)}", privateKey.Length, PrivateKeySize);
        Validation.EqualTo($"{nameof(seed)}.{nameof(seed.Length)}", seed.Length, SeedSize);
        Sodium.Initialize();
        int ret = crypto_kem_xwing_seed_keypair(publicKey, privateKey, seed);
        if (ret != 0) { throw new CryptographicException("Error generating key pair from seed."); }
    }

    public static void Encapsulate(Span<byte> sharedSecret, Span<byte> ciphertext, ReadOnlySpan<byte> recipientPublicKey)
    {
        Validation.EqualTo($"{nameof(sharedSecret)}.{nameof(sharedSecret.Length)}", sharedSecret.Length, SharedSecretSize);
        Validation.EqualTo($"{nameof(ciphertext)}.{nameof(ciphertext.Length)}", ciphertext.Length, CiphertextSize);
        Validation.EqualTo($"{nameof(recipientPublicKey)}.{nameof(recipientPublicKey.Length)}", recipientPublicKey.Length, PublicKeySize);
        Sodium.Initialize();
        int ret = crypto_kem_xwing_enc(ciphertext, sharedSecret, recipientPublicKey);
        if (ret != 0) { throw new CryptographicException("Error encapsulating."); }
    }

    public static void Decapsulate(Span<byte> sharedSecret, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> recipientPrivateKey)
    {
        Validation.EqualTo($"{nameof(sharedSecret)}.{nameof(sharedSecret.Length)}", sharedSecret.Length, SharedSecretSize);
        Validation.EqualTo($"{nameof(ciphertext)}.{nameof(ciphertext.Length)}", ciphertext.Length, CiphertextSize);
        Validation.EqualTo($"{nameof(recipientPrivateKey)}.{nameof(recipientPrivateKey.Length)}", recipientPrivateKey.Length, PrivateKeySize);
        Sodium.Initialize();
        int ret = crypto_kem_xwing_dec(sharedSecret, ciphertext, recipientPrivateKey);
        if (ret != 0) { throw new CryptographicException("Error decapsulating."); }
    }
}
