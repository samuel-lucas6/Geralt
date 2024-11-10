using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class AEGIS256
{
    public const int KeySize = crypto_aead_aegis256_KEYBYTES;
    public const int NonceSize = crypto_aead_aegis256_NPUBBYTES;
    public const int TagSize = crypto_aead_aegis256_ABYTES;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialize();
        int ret = crypto_aead_aegis256_encrypt(ciphertext, ciphertextLength: out _, plaintext, (ulong)plaintext.Length, associatedData, (ulong)associatedData.Length, nsec: null, nonce, key);
        if (ret != 0) { throw new CryptographicException("Error encrypting plaintext."); }
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialize();
        int ret = crypto_aead_aegis256_decrypt(plaintext, plaintextLength: out _, nsec: null, ciphertext, (ulong)ciphertext.Length, associatedData, (ulong)associatedData.Length, nonce, key);
        if (ret != 0) { throw new CryptographicException("Invalid authentication tag for the given inputs."); }
    }
}
