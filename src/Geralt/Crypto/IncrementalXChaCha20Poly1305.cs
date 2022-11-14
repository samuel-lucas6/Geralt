using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalXChaCha20Poly1305 : IDisposable
{
    private crypto_secretstream_xchacha20poly1305_state _state;
    private bool _forDecryption;

    /// <summary>
    /// Size of the authentication tag which gets appended to each ciphertext chunk.
    /// </summary>
    public const int TagSize = crypto_secretstream_xchacha20poly1305_ABYTES;

    /// <summary>
    /// Size of the header, which gets created when initializing for encryption and must be provided back when initializing for decryption.
    /// </summary>
    public const int HeaderBytes = crypto_secretstream_xchacha20poly1305_HEADERBYTES;

    /// <summary>
    /// Size of the secret key used to encrypt and decrypt a message.
    /// </summary>
    public const int KeySize = crypto_secretstream_xchacha20poly1305_KEYBYTES;

    /// <summary>
    /// No information is added to the nature of the message.
    /// </summary>
    public const byte TagMessage = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

    /// <summary>
    /// Mark the end of the stream.
    /// </summary>
    public const byte TagFinal = crypto_secretstream_xchacha20poly1305_TAG_FINAL;

    /// <summary>
    /// Mark the end of a sequence of messages, but not the end of the stream.
    /// </summary>
    public const byte TagPush = crypto_secretstream_xchacha20poly1305_TAG_PUSH;

    /// <summary>
    /// "Forget" the current secret key and derive a new one.
    /// </summary>
    public const byte TagReKey = crypto_secretstream_xchacha20poly1305_TAG_REKEY;

    public IncrementalXChaCha20Poly1305(bool forDecryption, Span<byte> header, ReadOnlySpan<byte> key)
    {
        _forDecryption = forDecryption;
        Validation.EqualToSize(nameof(header), header.Length, HeaderBytes);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialise();
        Initialize(header, key);
    }

    private unsafe void Initialize(Span<byte> header, ReadOnlySpan<byte> key)
    {
        fixed (byte* k = key, h = header)
        {
            int ret = _forDecryption
                ? crypto_secretstream_xchacha20poly1305_init_pull(ref _state, h, k)
                : crypto_secretstream_xchacha20poly1305_init_push(ref _state, h, k);
            if (ret != 0) { throw new CryptographicException("Error initializing stream encryption/decryption."); }
        }
    }

    public unsafe void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, byte tag = TagMessage)
    {
        if (_forDecryption) { throw new InvalidOperationException("Cannot push into a decryption stream."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);
        fixed (byte* c = ciphertextChunk, p = plaintextChunk)
        {
            int ret = crypto_secretstream_xchacha20poly1305_push(ref _state, c, out _, p, (ulong)plaintextChunk.Length, null, 0, tag);
            if (ret != 0) { throw new CryptographicException("Error encrypting plaintext chunk."); }
        }
    }

    public unsafe void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData, byte tag = TagMessage)
    {
        if (_forDecryption) { throw new InvalidOperationException("Cannot push into a decryption stream."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);
        fixed (byte* c = ciphertextChunk, p = plaintextChunk, a = associatedData)
        {
            int ret = crypto_secretstream_xchacha20poly1305_push(ref _state, c, out _, p, (ulong)plaintextChunk.Length, a, (ulong)associatedData.Length, tag);
            if (ret != 0) { throw new CryptographicException("Error encrypting plaintext chunk."); }
        }
    }

    public unsafe void Pull(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData, ref byte tag)
    {
        if (!_forDecryption) { throw new InvalidOperationException("Cannot pull from an encryption stream."); }
        Validation.EqualToSize(nameof(plaintextChunk), plaintextChunk.Length, ciphertextChunk.Length - TagSize);
        fixed (byte* c = ciphertextChunk, p = plaintextChunk, a = associatedData)
        {
            int ret = crypto_secretstream_xchacha20poly1305_pull(ref _state, p, out _, ref tag, c, (ulong)ciphertextChunk.Length, a, (ulong)associatedData.Length);
            if (ret != 0) { throw new CryptographicException("Error decrypting ciphertext chunk."); }
        }
    }

    public unsafe void Pull(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ref byte tag)
    {
        if (!_forDecryption) { throw new InvalidOperationException("Cannot pull from an encryption stream."); }
        fixed (byte* c = ciphertextChunk, p = plaintextChunk)
        {
            int ret = crypto_secretstream_xchacha20poly1305_pull(ref _state, p, out _, ref tag, c, (ulong)ciphertextChunk.Length, null, 0);
            if (ret != 0) { throw new CryptographicException("Error decrypting ciphertext chunk."); }
        }
    }

    public unsafe void ReKey()
    {
        crypto_secretstream_xchacha20poly1305_rekey(ref _state);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}