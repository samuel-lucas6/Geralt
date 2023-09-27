using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class AEGIS128L
{
    public const int KeySize = crypto_aead_aegis128l_KEYBYTES;
    public const int NonceSize = crypto_aead_aegis128l_NPUBBYTES;
    public const int TagSize = crypto_aead_aegis128l_ABYTES;

    public static unsafe void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialize();
        fixed (byte* c = ciphertext, p = plaintext, n = nonce, k = key, ad = associatedData)
        {
            int ret = crypto_aead_aegis128l_encrypt(c, ciphertextLength: out _, p, (ulong)plaintext.Length, ad, (ulong)associatedData.Length, nsec: null, n, k);
            if (ret != 0) { throw new CryptographicException("Error encrypting plaintext."); }
        }
    }

    public static unsafe void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialize();
        fixed (byte* p = plaintext, c = ciphertext, n = nonce, k = key, ad = associatedData)
        {
            int ret = crypto_aead_aegis128l_decrypt(p, plaintextLength: out _, nsec: null, c, (ulong)ciphertext.Length, ad, (ulong)associatedData.Length, n, k);
            if (ret != 0) { throw new CryptographicException("Invalid authentication tag for the given inputs."); }
        }
    }
}
