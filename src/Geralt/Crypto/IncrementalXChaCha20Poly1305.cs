using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalXChaCha20Poly1305 : IDisposable
{
    private crypto_secretstream_xchacha20poly1305_state _state;
    private readonly bool _decryption;

    /// <summary>
    /// Size of the authentication tag which gets appended to each ciphertext chunk.
    /// </summary>
    public const int TagSize = crypto_secretstream_xchacha20poly1305_ABYTES;

    /// <summary>
    /// Size of the header, which gets created when initializing for encryption and must be provided back when initializing for decryption.
    /// </summary>
    public const int HeaderSize = crypto_secretstream_xchacha20poly1305_HEADERBYTES;

    /// <summary>
    /// Size of the secret key used to encrypt and decrypt a message.
    /// </summary>
    public const int KeySize = crypto_secretstream_xchacha20poly1305_KEYBYTES;

    public enum StreamFlag
    {
        /// <summary>
        /// No information is added about the nature of the message.
        /// </summary>
        Message = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,

        /// <summary>
        /// Mark the end of a sequence of messages, but not the end of the stream.
        /// </summary>
        Push = crypto_secretstream_xchacha20poly1305_TAG_PUSH,

        /// <summary>
        /// "Forget" the current secret key and derive a new one.
        /// </summary>
        Rekey = crypto_secretstream_xchacha20poly1305_TAG_REKEY,

        /// <summary>
        /// Mark the end of the stream.
        /// </summary>
        Final = crypto_secretstream_xchacha20poly1305_TAG_FINAL
    }

    public IncrementalXChaCha20Poly1305(bool decryption, Span<byte> header, ReadOnlySpan<byte> key)
    {
        _decryption = decryption;
        Validation.EqualToSize(nameof(header), header.Length, HeaderSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialise();
        Initialize(header, key);
    }

    private unsafe void Initialize(Span<byte> header, ReadOnlySpan<byte> key)
    {
        fixed (byte* k = key, h = header)
        {
            int ret = _decryption
                ? crypto_secretstream_xchacha20poly1305_init_pull(ref _state, h, k)
                : crypto_secretstream_xchacha20poly1305_init_push(ref _state, h, k);
            if (ret != 0) { throw new CryptographicException("Error initializing stream encryption/decryption."); }
        }
    }

    public unsafe void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, StreamFlag flag = StreamFlag.Message, ReadOnlySpan<byte> associatedData = default)
    {
        if (_decryption) { throw new InvalidOperationException("Cannot push into a decryption stream."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);
        fixed (byte* c = ciphertextChunk, p = plaintextChunk, a = associatedData)
        {
            int ret = crypto_secretstream_xchacha20poly1305_push(ref _state, c, out _, p, (ulong)plaintextChunk.Length, a, (ulong)associatedData.Length, (byte)(int)flag);
            if (ret != 0) { throw new CryptographicException("Error encrypting plaintext chunk."); }
        }
    }

    public unsafe void Pull(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ref StreamFlag flag, ReadOnlySpan<byte> associatedData = default)
    {
        if (!_decryption) { throw new InvalidOperationException("Cannot pull from an encryption stream."); }
        Validation.EqualToSize(nameof(plaintextChunk), plaintextChunk.Length, ciphertextChunk.Length - TagSize);
        fixed (byte* c = ciphertextChunk, p = plaintextChunk, a = associatedData)
        {
            byte outFlag = 0x00;
            int ret = crypto_secretstream_xchacha20poly1305_pull(ref _state, p, out _, ref outFlag, c, (ulong)ciphertextChunk.Length, a, (ulong)associatedData.Length);
            flag = (StreamFlag)(int)outFlag;
            if (ret != 0) { throw new CryptographicException("Error decrypting ciphertext chunk."); }
        }
    }

    public unsafe void Pull(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ref StreamFlag flag)
    {
        if (!_decryption) { throw new InvalidOperationException("Cannot pull from an encryption stream."); }
        fixed (byte* c = ciphertextChunk, p = plaintextChunk)
        {
            byte outFlag = 0x00;
            int ret = crypto_secretstream_xchacha20poly1305_pull(ref _state, p, out _, ref outFlag, c, (ulong)ciphertextChunk.Length, null, 0);
            flag = (StreamFlag)(int)outFlag;
            if (ret != 0) { throw new CryptographicException("Error decrypting ciphertext chunk."); }
        }
    }

    public unsafe void Rekey()
    {
        crypto_secretstream_xchacha20poly1305_rekey(ref _state);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}