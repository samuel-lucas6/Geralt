using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class XChaCha20
{
    public const int KeySize = crypto_stream_xchacha20_KEYBYTES;
    public const int NonceSize = crypto_stream_xchacha20_NONCEBYTES;
    public const int BlockSize = 64;

    public static unsafe void Fill(Span<byte> buffer, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialize();
        fixed (byte* b = buffer, n = nonce, k = key)
        {
            int ret = crypto_stream_xchacha20(b, (ulong)buffer.Length, n, k);
            if (ret != 0) { throw new CryptographicException("Error computing pseudorandom bytes."); }
        }
    }

    public static unsafe void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ulong counter = 0)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialize();
        fixed (byte* c = ciphertext, p = plaintext, n = nonce, k = key)
        {
            int ret = crypto_stream_xchacha20_xor_ic(c, p, (ulong)plaintext.Length, n, counter, k);
            if (ret != 0) { throw new CryptographicException("Error encrypting plaintext."); }
        }
    }

    public static unsafe void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ulong counter = 0)
    {
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialize();
        fixed (byte* p = plaintext, c = ciphertext, n = nonce, k = key)
        {
            int ret = crypto_stream_xchacha20_xor_ic(p, c, (ulong)ciphertext.Length, n, counter, k);
            if (ret != 0) { throw new CryptographicException("Error decrypting ciphertext."); }
        }
    }
}
