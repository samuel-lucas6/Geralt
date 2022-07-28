using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class XChaCha20Poly1305Tests
{
    // draft-irtf-cfrg-xchacha-01 Section A.3.1: https://tools.ietf.org/id/draft-irtf-cfrg-xchacha-01.html#aeadxchacha20poly1305-1
    private static readonly byte[] Plaintext = Convert.FromHexString("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
    private static readonly byte[] Ciphertext = Convert.FromHexString("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49");
    private static readonly byte[] Nonce = Convert.FromHexString("404142434445464748494a4b4c4d4e4f5051525354555657");
    private static readonly byte[] Key = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private static readonly byte[] AssociatedData = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
    
    [TestMethod]
    public void Encrypt_ValidInputs()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + XChaCha20Poly1305.TagSize];
        XChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, Key, AssociatedData);
        Assert.IsTrue(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_DifferentPlaintext()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + XChaCha20Poly1305.TagSize];
        Span<byte> plaintext = Plaintext.ToArray();
        plaintext[0]++;
        XChaCha20Poly1305.Encrypt(ciphertext, plaintext, Nonce, Key);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_DifferentNonce()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + XChaCha20Poly1305.TagSize];
        Span<byte> nonce = Nonce.ToArray();
        nonce[0]++;
        XChaCha20Poly1305.Encrypt(ciphertext, Plaintext, nonce, Key);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_DifferentKey()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + XChaCha20Poly1305.TagSize];
        Span<byte> key = Key.ToArray();
        key[0]++;
        XChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, key);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_DifferentAssociatedData()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + XChaCha20Poly1305.TagSize];
        Span<byte> associatedData = AssociatedData.ToArray();
        associatedData[0]++;
        XChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, Key, associatedData);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_InvalidCiphertext()
    {
        var ciphertext = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, Key));
    }
    
    [TestMethod]
    public void Encrypt_InvalidPlaintext()
    {
        var ciphertext = new byte[Plaintext.Length + XChaCha20Poly1305.TagSize];
        var plaintext = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Encrypt(ciphertext, plaintext, Nonce, Key));
    }
    
    [TestMethod]
    public void Encrypt_InvalidNonce()
    {
        var ciphertext = new byte[Plaintext.Length + XChaCha20Poly1305.TagSize];
        var nonce = new byte[XChaCha20Poly1305.NonceSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Encrypt(ciphertext, Plaintext, nonce, Key));
        nonce = new byte[XChaCha20Poly1305.NonceSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Encrypt(ciphertext, Plaintext, nonce, Key));
    }
    
    [TestMethod]
    public void Encrypt_InvalidKey()
    {
        var ciphertext = new byte[Plaintext.Length + XChaCha20Poly1305.TagSize];
        var key = new byte[XChaCha20Poly1305.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, key));
        key = new byte[XChaCha20Poly1305.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, key));
    }
    
    [TestMethod]
    public void Decrypt_ValidInputs()
    {
        Span<byte> plaintext = stackalloc byte[Ciphertext.Length - XChaCha20Poly1305.TagSize];
        XChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, Key, AssociatedData);
        Assert.IsTrue(plaintext.SequenceEqual(Plaintext));
    }
    
    [TestMethod]
    public void Decrypt_InvalidPlaintext()
    {
        var plaintext = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, Key));
    }
    
    [TestMethod]
    public void Decrypt_InvalidCiphertext()
    {
        var plaintext = new byte[Ciphertext.Length - XChaCha20Poly1305.TagSize];
        var ciphertext = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Decrypt(plaintext, ciphertext, Nonce, Key));
    }
    
    [TestMethod]
    public void Decrypt_InvalidNonce()
    {
        var plaintext = new byte[Ciphertext.Length - XChaCha20Poly1305.TagSize];
        var nonce = new byte[XChaCha20Poly1305.NonceSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Decrypt(plaintext, Ciphertext, nonce, Key));
        nonce = new byte[XChaCha20Poly1305.NonceSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Decrypt(plaintext, Ciphertext, nonce, Key));
    }
    
    [TestMethod]
    public void Decrypt_InvalidKey()
    {
        var plaintext = new byte[Ciphertext.Length - XChaCha20Poly1305.TagSize];
        var key = new byte[XChaCha20Poly1305.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, key));
        key = new byte[XChaCha20Poly1305.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, key));
    }
    
    [TestMethod]
    public void Decrypt_WrongCiphertext()
    {
        var plaintext = new byte[Ciphertext.Length - XChaCha20Poly1305.TagSize];
        var ciphertext = Ciphertext.ToArray();
        ciphertext[0]++;
        Assert.ThrowsException<CryptographicException>(() => XChaCha20Poly1305.Decrypt(plaintext, ciphertext, Nonce, Key, AssociatedData));
    }
    
    [TestMethod]
    public void Decrypt_WrongTag()
    {
        var plaintext = new byte[Ciphertext.Length - XChaCha20Poly1305.TagSize];
        var ciphertext = Ciphertext.ToArray();
        ciphertext[^1]++;
        Assert.ThrowsException<CryptographicException>(() => XChaCha20Poly1305.Decrypt(plaintext, ciphertext, Nonce, Key, AssociatedData));
    }

    [TestMethod]
    public void Decrypt_WrongNonce()
    {
        var plaintext = new byte[Ciphertext.Length - XChaCha20Poly1305.TagSize];
        var nonce = Nonce.ToArray();
        nonce[0]++;
        Assert.ThrowsException<CryptographicException>(() => XChaCha20Poly1305.Decrypt(plaintext, Ciphertext, nonce, Key, AssociatedData));
    }
    
    [TestMethod]
    public void Decrypt_WrongKey()
    {
        var plaintext = new byte[Ciphertext.Length - XChaCha20Poly1305.TagSize];
        var key = Key.ToArray();
        key[0]++;
        Assert.ThrowsException<CryptographicException>(() => XChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, key, AssociatedData));
    }
    
    [TestMethod]
    public void Decrypt_WrongAssociatedData()
    {
        var plaintext = new byte[Ciphertext.Length - XChaCha20Poly1305.TagSize];
        var associatedData = AssociatedData.ToArray();
        associatedData[0]++;
        Assert.ThrowsException<CryptographicException>(() => XChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, Key, associatedData));
    }
}