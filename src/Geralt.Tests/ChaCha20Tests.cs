using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class ChaCha20Tests
{
    // RFC 8439 Appendix A.2: https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.2
    private static readonly byte[] Plaintext = Convert.FromHexString("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    private static readonly byte[] Ciphertext = Convert.FromHexString("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    private static readonly byte[] Nonce = Convert.FromHexString("000000000000000000000000");
    private static readonly byte[] Key = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000000");
    
    [TestMethod]
    public void Encrypt_ValidInputs()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length];
        ChaCha20.Encrypt(ciphertext, Plaintext, Nonce, Key);
        Assert.IsTrue(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_DifferentPlaintext()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length];
        Span<byte> plaintext = Plaintext.ToArray();
        plaintext[0]++;
        ChaCha20.Encrypt(ciphertext, plaintext, Nonce, Key);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_DifferentNonce()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length];
        Span<byte> nonce = Nonce.ToArray();
        nonce[0]++;
        ChaCha20.Encrypt(ciphertext, Plaintext, nonce, Key);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_DifferentKey()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length];
        Span<byte> key = Key.ToArray();
        key[0]++;
        ChaCha20.Encrypt(ciphertext, Plaintext, Nonce, key);
        Assert.IsFalse(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_InvalidCiphertext()
    {
        var ciphertext = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Encrypt(ciphertext, Plaintext, Nonce, Key));
    }
    
    [TestMethod]
    public void Encrypt_InvalidPlaintext()
    {
        var ciphertext = new byte[Plaintext.Length];
        var plaintext = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Encrypt(ciphertext, plaintext, Nonce, Key));
    }
    
    [TestMethod]
    public void Encrypt_InvalidNonce()
    {
        var ciphertext = new byte[Plaintext.Length];
        var nonce = new byte[ChaCha20.NonceSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Encrypt(ciphertext, Plaintext, nonce, Key));
        nonce = new byte[ChaCha20.NonceSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Encrypt(ciphertext, Plaintext, nonce, Key));
    }
    
    [TestMethod]
    public void Encrypt_InvalidKey()
    {
        var ciphertext = new byte[Plaintext.Length];
        var key = new byte[ChaCha20.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Encrypt(ciphertext, Plaintext, Nonce, key));
        key = new byte[ChaCha20.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Encrypt(ciphertext, Plaintext, Nonce, key));
    }
    
    [TestMethod]
    public void Decrypt_ValidInputs()
    {
        Span<byte> plaintext = stackalloc byte[Ciphertext.Length];
        ChaCha20.Decrypt(plaintext, Ciphertext, Nonce, Key);
        Assert.IsTrue(plaintext.SequenceEqual(Plaintext));
    }
    
    [TestMethod]
    public void Decrypt_DifferentCiphertext()
    {
        Span<byte> plaintext = stackalloc byte[Ciphertext.Length];
        Span<byte> ciphertext = Ciphertext.ToArray();
        ciphertext[0]++;
        ChaCha20.Decrypt(plaintext, ciphertext, Nonce, Key);
        Assert.IsFalse(plaintext.SequenceEqual(Plaintext));
    }
    
    [TestMethod]
    public void Decrypt_DifferentNonce()
    {
        Span<byte> plaintext = stackalloc byte[Ciphertext.Length];
        Span<byte> nonce = Nonce.ToArray();
        nonce[0]++;
        ChaCha20.Decrypt(plaintext, Ciphertext, nonce, Key);
        Assert.IsFalse(plaintext.SequenceEqual(Plaintext));
    }
    
    [TestMethod]
    public void Decrypt_DifferentKey()
    {
        Span<byte> plaintext = stackalloc byte[Ciphertext.Length];
        Span<byte> key = Key.ToArray();
        key[0]++;
        ChaCha20.Decrypt(plaintext, Ciphertext, Nonce, key);
        Assert.IsFalse(plaintext.SequenceEqual(Plaintext));
    }
    
    [TestMethod]
    public void Decrypt_InvalidPlaintext()
    {
        var plaintext = Array.Empty<byte>();
        var ciphertext = new byte[Ciphertext.Length];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Decrypt(plaintext, ciphertext, Nonce, Key));
    }
    
    [TestMethod]
    public void Decrypt_InvalidCiphertext()
    {
        var plaintext = new byte[Ciphertext.Length];
        var ciphertext = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Decrypt(plaintext, ciphertext, Nonce, Key));
    }
    
    [TestMethod]
    public void Decrypt_InvalidNonce()
    {
        var plaintext = new byte[Ciphertext.Length];
        var nonce = new byte[ChaCha20.NonceSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Decrypt(plaintext, Ciphertext, nonce, Key));
        nonce = new byte[ChaCha20.NonceSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Decrypt(plaintext, Ciphertext, nonce, Key));
    }
    
    [TestMethod]
    public void Decrypt_InvalidKey()
    {
        var plaintext = new byte[Ciphertext.Length];
        var key = new byte[ChaCha20.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Decrypt(plaintext, Ciphertext, Nonce, key));
        key = new byte[ChaCha20.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Decrypt(plaintext, Ciphertext, Nonce, key));
    }
}