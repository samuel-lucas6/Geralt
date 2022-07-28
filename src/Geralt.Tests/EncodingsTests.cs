using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class EncodingsTests
{
    // Generated using libsodium-core
    private static readonly byte[] HexData = Encoding.UTF8.GetBytes("You disgust me. And deserve to die.");
    private static readonly byte[] Base64Data = Convert.FromHexString("f9971d7fd1e2de4540c817991dbcd9791c81f9faae6e8253d294dfe6de3a2411");
    private const string Hex = "596f752064697367757374206d652e20416e64206465736572766520746f206469652e";
    private const string HexWithSpaces = "59 6f 75 20 64 69 73 67 75 7374206d652e20416e64206465736572766520746f206469652e";
    private const string Base64 = "+Zcdf9Hi3kVAyBeZHbzZeRyB+fquboJT0pTf5t46JBE=";
    private const string Base64WithSpaces = "+Zc df 9Hi3k VAyBeZHbzZe RyB+fqub oJT0pT f5t46JBE=";
    private const string Base64NoPadding = "+Zcdf9Hi3kVAyBeZHbzZeRyB+fquboJT0pTf5t46JBE";
    private const string Base64Url = "-Zcdf9Hi3kVAyBeZHbzZeRyB-fquboJT0pTf5t46JBE=";
    private const string Base64UrlNoPadding = "-Zcdf9Hi3kVAyBeZHbzZeRyB-fquboJT0pTf5t46JBE";

    [TestMethod]
    public void ToHex_ValidInput()
    {
        string hex = Encodings.ToHex(HexData);
        Assert.IsTrue(hex.Equals(Hex));
    }
    
    [TestMethod]
    public void ToHex_InvalidInput()
    {
        var data = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Encodings.ToHex(data));
    }
    
    [TestMethod]
    public void FromHex_ValidInput()
    {
        byte[] data = Encodings.FromHex(Hex);
        Assert.IsTrue(data.SequenceEqual(HexData));
    }
    
    [TestMethod]
    public void FromHex_HexWithSpaces()
    {
        byte[] data = Encodings.FromHex(HexWithSpaces, ignoreChars: " ");
        Assert.IsTrue(data.SequenceEqual(HexData));
    }

    [TestMethod]
    public void FromHex_InvalidHex()
    {
        Assert.ThrowsException<FormatException>(() => Encodings.FromHex(Base64));
    }
    
    [TestMethod]
    public void ToBase64_ValidInput()
    {
        string base64 = Encodings.ToBase64(Base64Data);
        Assert.IsTrue(base64.Equals(Base64));
    }
    
    [TestMethod]
    public void ToBase64NoPadding_ValidInput()
    {
        string base64NoPadding = Encodings.ToBase64(Base64Data, Encodings.Base64Variant.OriginalNoPadding);
        Assert.IsTrue(base64NoPadding.Equals(Base64NoPadding));
    }
    
    [TestMethod]
    public void ToBase64Url_ValidInput()
    {
        string base64Url = Encodings.ToBase64(Base64Data, Encodings.Base64Variant.Url);
        Assert.IsTrue(base64Url.Equals(Base64Url));
    }
    
    [TestMethod]
    public void ToBase64UrlNoPadding_ValidInput()
    {
        string base64UrlNoPadding = Encodings.ToBase64(Base64Data, Encodings.Base64Variant.UrlNoPadding);
        Assert.IsTrue(base64UrlNoPadding.Equals(Base64UrlNoPadding));
    }
    
    [TestMethod]
    public void ToBase64_InvalidInput()
    {
        var data = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Encodings.ToBase64(data));
    }
    
    [TestMethod]
    public void FromBase64_ValidInput()
    {
        byte[] data = Encodings.FromBase64(Base64);
        Assert.IsTrue(data.SequenceEqual(Base64Data));
    }
    
    [TestMethod]
    public void FromBase64_Base64WithSpaces()
    {
        byte[] data = Encodings.FromBase64(Base64WithSpaces, ignoreChars: " ");
        Assert.IsTrue(data.SequenceEqual(Base64Data));
    }
    
    [TestMethod]
    public void FromBase64NoPadding_ValidInput()
    {
        byte[] data = Encodings.FromBase64(Base64NoPadding, Encodings.Base64Variant.OriginalNoPadding);
        Assert.IsTrue(data.SequenceEqual(Base64Data));
    }
    
    [TestMethod]
    public void FromBase64Url_ValidInput()
    {
        byte[] data = Encodings.FromBase64(Base64Url, Encodings.Base64Variant.Url);
        Assert.IsTrue(data.SequenceEqual(Base64Data));
    }
    
    [TestMethod]
    public void FromBase64UrlNoPadding_ValidInput()
    {
        byte[] data = Encodings.FromBase64(Base64UrlNoPadding, Encodings.Base64Variant.UrlNoPadding);
        Assert.IsTrue(data.SequenceEqual(Base64Data));
    }

    [TestMethod]
    public void FromBase64_InvalidBase64()
    {
        Assert.ThrowsException<FormatException>(() => Encodings.FromBase64(Hex));
    }
    
    [TestMethod]
    public void FromBase64_WrongBase64Variant()
    {
        Assert.ThrowsException<FormatException>(() => Encodings.FromBase64(Base64Url, Encodings.Base64Variant.OriginalNoPadding));
    }
}