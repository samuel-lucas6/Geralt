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
    
    [TestMethod]
    public void ComputeTag_ValidInputs()
    {
        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        Poly1305.ComputeTag(tag, Message, Key);
        Assert.IsTrue(tag.SequenceEqual(Tag));
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
    public void DeriveKey_InvalidTag()
    {
        var tag = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.ComputeTag(tag, Message, Key));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidMessage()
    {
        var tag = new byte[Poly1305.TagSize];
        var message = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.ComputeTag(tag, message, Key));
    }
    
    [TestMethod]
    public void DeriveKey_InvalidKey()
    {
        var tag = new byte[Poly1305.TagSize];
        var key = new byte[Poly1305.KeySize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.ComputeTag(tag, Message, key));
        key = new byte[Poly1305.KeySize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Poly1305.ComputeTag(tag, Message, key));
    }
}