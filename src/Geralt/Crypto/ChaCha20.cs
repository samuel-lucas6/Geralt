using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class ChaCha20
{
    public const int KeySize = crypto_stream_chacha20_ietf_KEYBYTES;
    public const int NonceSize = crypto_stream_chacha20_ietf_NONCEBYTES;

    public static unsafe void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length);
        Validation.NotEmpty(nameof(plaintext), plaintext.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialise();
        fixed (byte* c = ciphertext, p = plaintext, n = nonce, k = key)
        {
            int ret = crypto_stream_chacha20_ietf_xor(c, p, plaintext.Length, n, k);
            if (ret != 0) { throw new CryptographicException("Error encrypting plaintext."); }
        }
    }

    public static unsafe void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length);
        Validation.NotEmpty(nameof(ciphertext), ciphertext.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialise();
        fixed (byte* p = plaintext, c = ciphertext, n = nonce, k = key)
        {
            int ret = crypto_stream_chacha20_ietf_xor(p, c, ciphertext.Length, n, k);
            if (ret != 0) { throw new CryptographicException("Error decrypting ciphertext."); }
        }
    }
}