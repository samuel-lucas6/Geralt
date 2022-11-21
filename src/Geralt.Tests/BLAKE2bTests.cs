using System;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class BLAKE2bTests
{
    // RFC 7693 Appendix A: https://datatracker.ietf.org/doc/html/rfc7693#appendix-A
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("abc");
    private static readonly byte[] Hash = Convert.FromHexString("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    // Generated using libsodium-core
    private static readonly byte[] Key = Convert.FromHexString("dc1dcb9b0073a0e06dd2e04ad31d434f91cef039925218fe99d09311f4c1773f");
    private static readonly byte[] Tag = Convert.FromHexString("69fc5368a03ed0be533be600a6f5cc589c208da6e814eea28df1c57e8f6ce4d8");
    private static readonly byte[] DifferentKey = Convert.FromHexString("593d4b15f6fb98a16835f9ef6b67ed241678ab31756c2191dad397064b5e5849");
    private static readonly byte[] OutputKeyingMaterial = Convert.FromHexString("5fa348e4864e31b87f2b208d4191dd0395896b2a5b4d1120f43d68186542c67e");
    // Made up myself
    private static readonly byte[] Personalisation = Encoding.UTF8.GetBytes("Geralt.Personal!");
    private static readonly byte[] Salt = new byte[BLAKE2b.SaltSize];
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("ChaCha20-Poly1305 encryption key");
    
    [TestMethod]
    public void ComputeHash_ValidInputs()
    {
        Span<byte> hash = stackalloc byte[BLAKE2b.MaxHashSize];
        BLAKE2b.ComputeHash(hash, Message);
        Assert.IsTrue(hash.SequenceEqual(Hash));
    }
    
    [TestMethod]
    public void ComputeHash_EmptyMessage()
    {
        Span<byte> hash = stackalloc byte[BLAKE2b.MaxHashSize];
        Span<byte> message = Span<byte>.Empty;
        BLAKE2b.ComputeHash(hash, message);
        Assert.IsFalse(hash.SequenceEqual(new byte[hash.Length]));
        Assert.IsFalse(hash.SequenceEqual(Hash));
    }

    [TestMethod]
    public void ComputeHash_InvalidHash()
    {
        var hash = new byte[BLAKE2b.MinHashSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeHash(hash, Message));
        hash = new byte[BLAKE2b.MaxHashSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeHash(hash, Message));
    }
    
    [TestMethod]
    public void ComputeHashStream_ValidInputs()
    {
        Span<byte> hash = stackalloc byte[BLAKE2b.MaxHashSize];
        using var message = new MemoryStream(Message, writable: false);
        BLAKE2b.ComputeHash(hash, message);
        Assert.IsTrue(hash.SequenceEqual(Hash));
        message.Position = 0;
        BLAKE2b.ComputeHash(hash, message);
        Assert.IsTrue(hash.SequenceEqual(Hash));
    }
    
    [TestMethod]
    public void ComputeHashStream_EmptyMessage()
    {
        Span<byte> hash = stackalloc byte[BLAKE2b.MaxHashSize];
        using var message = new MemoryStream(Array.Empty<byte>(), writable: false);
        BLAKE2b.ComputeHash(hash, message);
        Assert.IsFalse(hash.SequenceEqual(new byte[hash.Length]));
        Assert.IsFalse(hash.SequenceEqual(Hash));
    }
    
    [TestMethod]
    public void ComputeHashStream_InvalidHash()
    {
        var hash = new byte[BLAKE2b.MinHashSize - 1];
        using var message = new MemoryStream(Message, writable: false);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeHash(hash, message));
        hash = new byte[BLAKE2b.MaxHashSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeHash(hash, message));
    }
    
    [TestMethod]
    public void ComputeHashStream_InvalidMessage()
    {
        var hash = new byte[BLAKE2b.MaxHashSize];
        using MemoryStream message = null;
        Assert.ThrowsException<ArgumentNullException>(() => BLAKE2b.ComputeHash(hash, message));
    }
    
    [TestMethod]
    public void ComputeTag_ValidInputs()
    {
        Span<byte> tag = stackalloc byte[BLAKE2b.TagSize];
        BLAKE2b.ComputeTag(tag, Message, Key);
        Assert.IsTrue(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void ComputeTag_EmptyMessage()
    {
        Span<byte> tag = stackalloc byte[BLAKE2b.TagSize];
        Span<byte> message = Span<byte>.Empty;
        BLAKE2b.ComputeTag(tag, message, Key);
        Assert.IsFalse(tag.SequenceEqual(new byte[tag.Length]));
        Assert.IsFalse(tag.SequenceEqual(Tag));
        bool valid = BLAKE2b.VerifyTag(tag, message, Key);
        Assert.IsTrue(valid);
    }
    
    [TestMethod]
    public void ComputeTag_DifferentKey()
    {
        Span<byte> tag = stackalloc byte[BLAKE2b.TagSize];
        BLAKE2b.ComputeTag(tag, Message, DifferentKey);
        Assert.IsFalse(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void ComputeTag_InvalidTag()
    {
        var tag = new byte[BLAKE2b.MinTagSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeTag(tag, Message, Key));
        tag = new byte[BLAKE2b.MaxTagSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeTag(tag, Message, Key));
    }
    
    [TestMethod]
    public void ComputeTag_InvalidKey()
    {
        var tag = new byte[BLAKE2b.TagSize];
        var key = new byte[BLAKE2b.MinKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeTag(tag, Message, key));
        key = new byte[BLAKE2b.MaxKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeTag(tag, Message, key));
    }

    [TestMethod]
    public void VerifyTag_ValidInputs()
    {
        bool valid = BLAKE2b.VerifyTag(Tag, Message, Key);
        Assert.IsTrue(valid);
    }
    
    [TestMethod]
    public void VerifyTag_DifferentTag()
    {
        bool valid = BLAKE2b.VerifyTag(DifferentKey, Message, Key);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void VerifyTag_DifferentMessage()
    {
        bool valid = BLAKE2b.VerifyTag(Tag, Hash, Key);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void VerifyTag_DifferentKey()
    {
        bool valid = BLAKE2b.VerifyTag(Tag, Message, DifferentKey);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void VerifyTag_InvalidTag()
    {
        var tag = new byte[BLAKE2b.MinTagSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.VerifyTag(tag, Message, Key));
        tag = new byte[BLAKE2b.MaxTagSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.VerifyTag(tag, Message, Key));
    }

    [TestMethod]
    public void VerifyTag_InvalidKey()
    {
        var tag = new byte[BLAKE2b.TagSize];
        var key = new byte[BLAKE2b.MinKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.VerifyTag(tag, Message, key));
        key = new byte[BLAKE2b.MaxKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.VerifyTag(tag, Message, key));
    }
    
    [TestMethod]
    public void DeriveKey_ValidInputs()
    {
        Span<byte> outputKeyingMaterial = stackalloc byte[BLAKE2b.KeySize];
        BLAKE2b.DeriveKey(outputKeyingMaterial, Key, Personalisation, Salt, Info);
        Assert.IsTrue(outputKeyingMaterial.SequenceEqual(OutputKeyingMaterial));
    }
    
    [TestMethod]
    public void DeriveKey_DifferentKey()
    {
        Span<byte> outputKeyingMaterial = stackalloc byte[BLAKE2b.KeySize];
        BLAKE2b.DeriveKey(outputKeyingMaterial, DifferentKey, Personalisation, Salt, Info);
        Assert.IsFalse(outputKeyingMaterial.SequenceEqual(OutputKeyingMaterial));
    }
    
    [TestMethod]
    public void DeriveKey_DifferentPersonalisation()
    {
        Span<byte> outputKeyingMaterial = stackalloc byte[BLAKE2b.KeySize];
        Span<byte> personalisation = Encoding.UTF8.GetBytes("#Cirilla Riannon");
        BLAKE2b.DeriveKey(outputKeyingMaterial, Key, personalisation, Salt, Info);
        Assert.IsFalse(outputKeyingMaterial.SequenceEqual(OutputKeyingMaterial));
    }
    
    [TestMethod]
    public void DeriveKey_DifferentSalt()
    {
        Span<byte> outputKeyingMaterial = stackalloc byte[BLAKE2b.KeySize];
        Span<byte> salt = stackalloc byte[BLAKE2b.SaltSize];
        salt[0]++;
        BLAKE2b.DeriveKey(outputKeyingMaterial, Key, Personalisation, salt, Info);
        Assert.IsFalse(outputKeyingMaterial.SequenceEqual(OutputKeyingMaterial));
    }
    
    [TestMethod]
    public void DeriveKey_DifferentInfo()
    {
        Span<byte> outputKeyingMaterial = stackalloc byte[BLAKE2b.KeySize];
        Span<byte> info = Encoding.UTF8.GetBytes("BLAKE2b MAC key");
        BLAKE2b.DeriveKey(outputKeyingMaterial, Key, Personalisation, Salt, info);
        Assert.IsFalse(outputKeyingMaterial.SequenceEqual(OutputKeyingMaterial));
    }
    
    [TestMethod]
    public void DeriveKey_NoInfo()
    {
        Span<byte> outputKeyingMaterial = stackalloc byte[BLAKE2b.KeySize];
        BLAKE2b.DeriveKey(outputKeyingMaterial, Key, Personalisation, Salt);
        Assert.IsFalse(outputKeyingMaterial.SequenceEqual(OutputKeyingMaterial));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidOutputKeyingMaterial()
    {
        var outputKeyingMaterial = new byte[BLAKE2b.MinKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.DeriveKey(outputKeyingMaterial, Key, Personalisation, Salt, Info));
        outputKeyingMaterial = new byte[BLAKE2b.MaxKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.DeriveKey(outputKeyingMaterial, Key, Personalisation, Salt, Info));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidInputKeyingMaterial()
    {
        var outputKeyingMaterial = new byte[BLAKE2b.KeySize];
        var inputKeyingMaterial = new byte[BLAKE2b.MinKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.DeriveKey(outputKeyingMaterial, inputKeyingMaterial, Personalisation, Salt, Info));
        inputKeyingMaterial = new byte[BLAKE2b.MaxKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.DeriveKey(outputKeyingMaterial, inputKeyingMaterial, Personalisation, Salt, Info));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidPersonalisation()
    {
        var outputKeyingMaterial = new byte[BLAKE2b.KeySize];
        var personalisation = new byte[BLAKE2b.PersonalSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.DeriveKey(outputKeyingMaterial, Key, personalisation, Salt, Info));
        personalisation = new byte[BLAKE2b.PersonalSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.DeriveKey(outputKeyingMaterial, Key, personalisation, Salt, Info));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidSalt()
    {
        var outputKeyingMaterial = new byte[BLAKE2b.KeySize];
        var salt = new byte[BLAKE2b.SaltSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.DeriveKey(outputKeyingMaterial, Key, Personalisation, salt, Info));
        salt = new byte[BLAKE2b.SaltSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BLAKE2b.DeriveKey(outputKeyingMaterial, Key, Personalisation, salt, Info));
    }
    
    [TestMethod]
    public void IncrementalHash_ValidInputs()
    {
        Span<byte> hash = stackalloc byte[BLAKE2b.MaxHashSize];
        using var blake2b = new IncrementalBLAKE2b(hash.Length);
        blake2b.Update(Message);
        blake2b.Finalize(hash);
        Assert.IsTrue(hash.SequenceEqual(Hash));
    }
    
    [TestMethod]
    public void IncrementalHash_EmptyMessage()
    {
        Span<byte> hash = stackalloc byte[BLAKE2b.MaxHashSize];
        Span<byte> message = Span<byte>.Empty;
        using var blake2b = new IncrementalBLAKE2b(hash.Length);
        blake2b.Update(message);
        blake2b.Finalize(hash);
        Assert.IsFalse(hash.SequenceEqual(new byte[hash.Length]));
        Assert.IsFalse(hash.SequenceEqual(Hash));
    }
    
    [TestMethod]
    public void IncrementalHash_InvalidHash()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new IncrementalBLAKE2b(BLAKE2b.MinHashSize - 1));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new IncrementalBLAKE2b(BLAKE2b.MaxHashSize + 1));
        using var blake2b = new IncrementalBLAKE2b(BLAKE2b.MaxHashSize);
        blake2b.Update(Message);
        var hash = new byte[BLAKE2b.MaxHashSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => blake2b.Finalize(hash));
        hash = new byte[BLAKE2b.MaxHashSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => blake2b.Finalize(hash));
    }
    
    [TestMethod]
    public void IncrementalTag_ValidInputs()
    {
        Span<byte> tag = stackalloc byte[BLAKE2b.TagSize];
        using var blake2b = new IncrementalBLAKE2b(tag.Length, Key);
        blake2b.Update(Message);
        blake2b.Finalize(tag);
        Assert.IsTrue(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void IncrementalTag_EmptyMessage()
    {
        Span<byte> tag = stackalloc byte[BLAKE2b.TagSize];
        Span<byte> message = Span<byte>.Empty;
        using var blake2b = new IncrementalBLAKE2b(tag.Length, Key);
        blake2b.Update(message);
        blake2b.Finalize(tag);
        Assert.IsFalse(tag.SequenceEqual(new byte[tag.Length]));
        Assert.IsFalse(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void IncrementalTag_DifferentKey()
    {
        Span<byte> tag = stackalloc byte[BLAKE2b.TagSize];
        Span<byte> key = Key.ToArray();
        key[0]++;
        using var blake2b = new IncrementalBLAKE2b(tag.Length, key);
        blake2b.Update(Message);
        blake2b.Finalize(tag);
        Assert.IsFalse(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void IncrementalTag_InvalidKey()
    {
        var key = new byte[BLAKE2b.MinKeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new IncrementalBLAKE2b(BLAKE2b.TagSize, key));
        key = new byte[BLAKE2b.MaxKeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new IncrementalBLAKE2b(BLAKE2b.TagSize, key));
    }
}