using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class ChaCha20
{
    public const int KeySize = crypto_stream_chacha20_ietf_KEYBYTES;
    public const int NonceSize = crypto_stream_chacha20_ietf_NONCEBYTES;
    public const int BlockSize = 64;

    public static void Fill(Span<byte> buffer, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialize();
        int ret = crypto_stream_chacha20_ietf(buffer, (ulong)buffer.Length, nonce, key);
        if (ret != 0) { throw new CryptographicException("Error computing pseudorandom bytes."); }
    }

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, uint counter = 0)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        ThrowIfCounterOverflow(plaintext.Length, counter);
        Sodium.Initialize();
        int ret = crypto_stream_chacha20_ietf_xor_ic(ciphertext, plaintext, (ulong)plaintext.Length, nonce, counter, key);
        if (ret != 0) { throw new CryptographicException("Error encrypting plaintext."); }
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, uint counter = 0)
    {
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        ThrowIfCounterOverflow(ciphertext.Length, counter);
        Sodium.Initialize();
        int ret = crypto_stream_chacha20_ietf_xor_ic(plaintext, ciphertext, (ulong)ciphertext.Length, nonce, counter, key);
        if (ret != 0) { throw new CryptographicException("Error decrypting ciphertext."); }
    }

    private static void ThrowIfCounterOverflow(int messageSize, uint counter)
    {
        long blockCount = (-1L + messageSize + BlockSize) / BlockSize;
        if (counter + blockCount > uint.MaxValue) {
            throw new CryptographicException("Counter overflow prevented.");
        }
    }
}
