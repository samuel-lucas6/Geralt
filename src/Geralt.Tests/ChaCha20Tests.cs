using System;
using System.Linq;
using System.Security.Cryptography;
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
    private static readonly byte[] CounterPlaintext = Convert.FromHexString("416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f");
    private static readonly byte[] CounterCiphertext = Convert.FromHexString("a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221");
    private static readonly byte[] CounterNonce = Convert.FromHexString("000000000000000000000002");
    private static readonly byte[] CounterKey = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000001");
    private const uint Counter = 1;
    private const uint OverflowCounter = uint.MaxValue - 5;

    [TestMethod]
    public void Encrypt_ValidInputs()
    {
        Span<byte> ciphertext = stackalloc byte[Plaintext.Length];
        ChaCha20.Encrypt(ciphertext, Plaintext, Nonce, Key);
        Assert.IsTrue(ciphertext.SequenceEqual(Ciphertext));
    }
    
    [TestMethod]
    public void Encrypt_EmptyPlaintext()
    {
        Span<byte> plaintext = Span<byte>.Empty;
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        ChaCha20.Encrypt(ciphertext, plaintext, Nonce, Key);
        Assert.IsTrue(plaintext.SequenceEqual(ciphertext));
        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        ChaCha20.Decrypt(decrypted, ciphertext, Nonce, Key);
        Assert.IsTrue(plaintext.SequenceEqual(decrypted));
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
    public void Encrypt_DifferentCounter()
    {
        Span<byte> ciphertext = stackalloc byte[CounterPlaintext.Length];
        ChaCha20.Encrypt(ciphertext, CounterPlaintext, CounterNonce, CounterKey, Counter);
        Assert.IsTrue(ciphertext.SequenceEqual(CounterCiphertext));
    }

    [TestMethod]
    public void Encrypt_InvalidCiphertext()
    {
        var ciphertext = new byte[Plaintext.Length - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Encrypt(ciphertext, Plaintext, Nonce, Key));
        ciphertext = new byte[Plaintext.Length + 1];
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
    public void Encrypt_CounterOverflow()
    {
        var ciphertext = new byte[CounterPlaintext.Length];
        Assert.ThrowsException<CryptographicException>(() => ChaCha20.Encrypt(ciphertext, CounterPlaintext, CounterNonce, CounterKey, OverflowCounter));
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
    public void Decrypt_DifferentCounter()
    {
        Span<byte> plaintext = stackalloc byte[CounterCiphertext.Length];
        ChaCha20.Decrypt(plaintext, CounterCiphertext, CounterNonce, CounterKey, Counter);
        Assert.IsTrue(plaintext.SequenceEqual(CounterPlaintext));
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
        var ciphertext = new byte[plaintext.Length - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaCha20.Decrypt(plaintext, ciphertext, Nonce, Key));
        ciphertext = new byte[plaintext.Length + 1];
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
    
    [TestMethod]
    public void Decrypt_CounterOverflow()
    {
        var plaintext = new byte[CounterCiphertext.Length];
        Assert.ThrowsException<CryptographicException>(() => ChaCha20.Decrypt(plaintext, CounterCiphertext, CounterNonce, CounterKey, OverflowCounter));
    }
}