using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class Poly1305Tests
{
    // RFC 8439 Section 2.5.2: https://datatracker.ietf.org/doc/html/rfc8439#section-2.5.2
    private static readonly byte[] Message = Convert.FromHexString("43727970746f6772617068696320466f72756d2052657365617263682047726f7570");
    private static readonly byte[] Tag = Convert.FromHexString("a8061dc1305136c6c22b8baf0c0127a9");
    private static readonly byte[] Key = Convert.FromHexString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    // Generated using libsodium-core
    private static readonly byte[] DifferentTag = Convert.FromHexString("bca21536da522787b9267be10c1b7499");
    private static readonly byte[] DifferentKey = Convert.FromHexString("593d4b15f6fb98a16835f9ef6b67ed241678ab31756c2191dad397064b5e5849");
    
    [TestMethod]
    public void ComputeTag_ValidInputs()
    {
        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        Poly1305.ComputeTag(tag, Message, Key);
        Assert.IsTrue(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void ComputeTag_EmptyMessage()
    {
        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        Span<byte> message = Span<byte>.Empty;
        Poly1305.ComputeTag(tag, message, Key);
        Assert.IsFalse(tag.SequenceEqual(Tag));
        bool valid = Poly1305.VerifyTag(tag, message, Key);
        Assert.IsTrue(valid);
    }
    
    [TestMethod]
    public void ComputeTag_DifferentMessage()
    {
        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        Span<byte> message = Message.ToArray();
        message[0]++;
        Poly1305.ComputeTag(tag, message, Key);
        Assert.IsFalse(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void ComputeTag_DifferentKey()
    {
        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        Span<byte> key = Key.ToArray();
        key[0]++;
        Poly1305.ComputeTag(tag, Message, key);
        Assert.IsFalse(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void ComputeTag_InvalidTag()
    {
        var tag = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.ComputeTag(tag, Message, Key));
    }
    
    [TestMethod]
    public void ComputeTag_InvalidKey()
    {
        var tag = new byte[Poly1305.TagSize];
        var key = new byte[Poly1305.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.ComputeTag(tag, Message, key));
        key = new byte[Poly1305.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.ComputeTag(tag, Message, key));
    }
    
    [TestMethod]
    public void VerifyTag_ValidInputs()
    {
        bool valid = Poly1305.VerifyTag(Tag, Message, Key);
        Assert.IsTrue(valid);
    }
    
    [TestMethod]
    public void VerifyTag_DifferentTag()
    {
        bool valid = Poly1305.VerifyTag(DifferentTag, Message, Key);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void VerifyTag_DifferentMessage()
    {
        bool valid = Poly1305.VerifyTag(Tag, DifferentTag, Key);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void VerifyTag_DifferentKey()
    {
        bool valid = Poly1305.VerifyTag(Tag, Message, DifferentKey);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void VerifyTag_InvalidTag()
    {
        var tag = new byte[Poly1305.TagSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.VerifyTag(tag, Message, Key));
        tag = new byte[Poly1305.TagSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.VerifyTag(tag, Message, Key));
    }

    [TestMethod]
    public void VerifyTag_InvalidKey()
    {
        var tag = new byte[Poly1305.TagSize];
        var key = new byte[Poly1305.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.VerifyTag(tag, Message, key));
        key = new byte[Poly1305.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.VerifyTag(tag, Message, key));
    }
}