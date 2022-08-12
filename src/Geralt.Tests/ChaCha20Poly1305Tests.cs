using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class ChaCha20Poly1305Tests
{
    // RFC 8439 Section 2.8.2: https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    private static readonly byte[] Plaintext = Convert.FromHexString("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
    private static readonly byte[] Ciphertext = Convert.FromHexString("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
    private static readonly byte[] Nonce = Convert.FromHexString("070000004041424344454647");
    private static readonly byte[] Key = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private static readonly byte[] AssociatedData = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
    
    [TestMethod]
    public void Encrypt_ValidInputs()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + ChaCha20Poly1305.TagSize];
        ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, Key, AssociatedData);
        Assert.IsTrue(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_EmptyPlaintext()
    {
        Span<byte> plaintext = Span<byte>.Empty;
        Span<byte> ciphertext = stackalloc byte[plaintext.Length + ChaCha20Poly1305.TagSize];
        ChaCha20Poly1305.Encrypt(ciphertext, plaintext, Nonce, Key);
        Assert.IsFalse(ciphertext.SequenceEqual(new byte[ciphertext.Length]));
        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        ChaCha20Poly1305.Decrypt(decrypted, ciphertext, Nonce, Key);
        Assert.IsTrue(plaintext.SequenceEqual(decrypted));
    }
    
    [TestMethod]
    public void Encrypt_DifferentNonce()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + ChaCha20Poly1305.TagSize];
        Span<byte> nonce = Nonce.ToArray();
        nonce[0]++;
        ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, nonce, Key);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_DifferentKey()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + ChaCha20Poly1305.TagSize];
        Span<byte> key = Key.ToArray();
        key[0]++;
        ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, key);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_DifferentAssociatedData()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length + ChaCha20Poly1305.TagSize];
        Span<byte> associatedData = AssociatedData.ToArray();
        associatedData[0]++;
        ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, Key, associatedData);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_InvalidCiphertext()
    {
        var ciphertext = new byte[Plaintext.Length + ChaCha20Poly1305.TagSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, Key));
        ciphertext = new byte[Plaintext.Length + ChaCha20Poly1305.TagSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, Key));
    }

    [TestMethod]
    public void Encrypt_InvalidNonce()
    {
        var ciphertext = new byte[Plaintext.Length + ChaCha20Poly1305.TagSize];
        var nonce = new byte[ChaCha20Poly1305.NonceSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, nonce, Key));
        nonce = new byte[ChaCha20Poly1305.NonceSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, nonce, Key));
    }
    
    [TestMethod]
    public void Encrypt_InvalidKey()
    {
        var ciphertext = new byte[Plaintext.Length + ChaCha20Poly1305.TagSize];
        var key = new byte[ChaCha20Poly1305.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, key));
        key = new byte[ChaCha20Poly1305.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Encrypt(ciphertext, Plaintext, Nonce, key));
    }
    
    [TestMethod]
    public void Decrypt_ValidInputs()
    {
        Span<byte> plaintext = stackalloc byte[Ciphertext.Length - ChaCha20Poly1305.TagSize];
        ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, Key, AssociatedData);
        Assert.IsTrue(plaintext.SequenceEqual(Plaintext));
    }

    [TestMethod]
    public void Decrypt_WrongCiphertext()
    {
        var plaintext = new byte[Ciphertext.Length - ChaCha20Poly1305.TagSize];
        var ciphertext = Ciphertext.ToArray();
        ciphertext[0]++;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Poly1305.Decrypt(plaintext, ciphertext, Nonce, Key, AssociatedData));
    }
    
    [TestMethod]
    public void Decrypt_WrongTag()
    {
        var plaintext = new byte[Ciphertext.Length - ChaCha20Poly1305.TagSize];
        var ciphertext = Ciphertext.ToArray();
        ciphertext[^1]++;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Poly1305.Decrypt(plaintext, ciphertext, Nonce, Key, AssociatedData));
    }
    
    [TestMethod]
    public void Decrypt_WrongNonce()
    {
        var plaintext = new byte[Ciphertext.Length - ChaCha20Poly1305.TagSize];
        var nonce = Nonce.ToArray();
        nonce[0]++;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, nonce, Key, AssociatedData));
    }
    
    [TestMethod]
    public void Decrypt_WrongKey()
    {
        var plaintext = new byte[Ciphertext.Length - ChaCha20Poly1305.TagSize];
        var key = Key.ToArray();
        key[0]++;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, key, AssociatedData));
    }
    
    [TestMethod]
    public void Decrypt_WrongAssociatedData()
    {
        var plaintext = new byte[Ciphertext.Length - ChaCha20Poly1305.TagSize];
        var associatedData = AssociatedData.ToArray();
        associatedData[0]++;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, Key, associatedData));
    }
    
    [TestMethod]
    public void Decrypt_InvalidPlaintext()
    {
        var plaintext = new byte[Ciphertext.Length - ChaCha20Poly1305.TagSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, Key));
        plaintext = new byte[Ciphertext.Length - ChaCha20Poly1305.TagSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, Key));
    }

    [TestMethod]
    public void Decrypt_InvalidNonce()
    {
        var plaintext = new byte[Ciphertext.Length - ChaCha20Poly1305.TagSize];
        var nonce = new byte[ChaCha20Poly1305.NonceSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, nonce, Key));
        nonce = new byte[ChaCha20Poly1305.NonceSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, nonce, Key));
    }
    
    [TestMethod]
    public void Decrypt_InvalidKey()
    {
        var plaintext = new byte[Ciphertext.Length - ChaCha20Poly1305.TagSize];
        var key = new byte[ChaCha20Poly1305.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, key));
        key = new byte[ChaCha20Poly1305.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Decrypt(plaintext, Ciphertext, Nonce, key));
    }
}