using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class EncodingsTests
{
    // https://www.rfc-editor.org/rfc/rfc4648#section-10
    public static IEnumerable<object[]> Rfc4648TestVectors()
    {
        yield return new object[] { "Zg==", "f", Encodings.Base64Variant.Original };
        yield return new object[] { "Zm8=", "fo", Encodings.Base64Variant.Original };
        yield return new object[] { "Zm9v", "foo", Encodings.Base64Variant.Original };
        yield return new object[] { "Zm9vYg==", "foob", Encodings.Base64Variant.Original };
        yield return new object[] { "Zm9vYmE=", "fooba", Encodings.Base64Variant.Original };
        yield return new object[] { "Zm9vYmFy", "foobar", Encodings.Base64Variant.Original };
    }
    
    // https://eprint.iacr.org/2022/361
    // https://base64.guru/standards/base64url
    public static IEnumerable<object[]> Base64VariantTestVectors()
    {
        yield return new object[] { "SGVsbG8=", "Hello", Encodings.Base64Variant.Original };
        yield return new object[] { "SGVsbA==", "Hell", Encodings.Base64Variant.Original };
        yield return new object[] { "PDw/Pz8+Pg", "<<???>>", Encodings.Base64Variant.OriginalNoPadding };
        yield return new object[] { "PDw_Pz8-Pg==", "<<???>>", Encodings.Base64Variant.Url };
        yield return new object[] { "PDw_Pz8-Pg", "<<???>>", Encodings.Base64Variant.UrlNoPadding };
    }
    
    [TestMethod]
    [DataRow("596f752064697367757374206d652e20416e64206465736572766520746f206469652e", "You disgust me. And deserve to die.")]
    public void ToHex_Valid(string hex, string data)
    {
        Span<byte> d = Encoding.UTF8.GetBytes(data);
        
        string h = Encodings.ToHex(d);
        
        Assert.AreEqual(hex, h);
    }
    
    [TestMethod]
    public void ToHex_Invalid()
    {
        var d = Array.Empty<byte>();
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Encodings.ToHex(d));
    }
    
    [TestMethod]
    [DataRow("fo", "666f", "")]
    [DataRow("foo", "666F6F", "")]
    [DataRow("foob", "66 6f 6f 62", " ")]
    [DataRow("fooba", "66:6f:6f:62:61", ":")]
    [DataRow("foobar", "66 : 6f : 6f : 62 : 61 : 72", ": ")]
    public void FromHex_Valid(string data, string hex, string ignoreChars)
    {
        byte[] d = Encodings.FromHex(hex, ignoreChars);
        
        Assert.AreEqual(data, Encoding.UTF8.GetString(d));
    }
    
    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("Zg==")]
    [DataRow("66/6f/6f")]
    public void FromHex_Invalid(string hex)
    {
        if (hex == null) {
            Assert.ThrowsException<ArgumentNullException>(() => Encodings.FromHex(hex));
        }
        else if (hex == "") {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => Encodings.FromHex(hex));
        }
        else {
            Assert.ThrowsException<FormatException>(() => Encodings.FromHex(hex));
        }
    }
    
    [TestMethod]
    [DynamicData(nameof(Rfc4648TestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(Base64VariantTestVectors), DynamicDataSourceType.Method)]
    public void ToBase64_Valid(string base64, string data, Encodings.Base64Variant variant)
    {
        Span<byte> d = Encoding.UTF8.GetBytes(data);
        
        string b = Encodings.ToBase64(d, variant);
        
        Assert.AreEqual(base64, b);
    }
    
    [TestMethod]
    public void ToBase64_Invalid()
    {
        var d = Array.Empty<byte>();
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Encodings.ToBase64(d));
    }
    
    [TestMethod]
    [DynamicData(nameof(Rfc4648TestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(Base64VariantTestVectors), DynamicDataSourceType.Method)]
    public void FromBase64_Valid(string base64, string data, Encodings.Base64Variant variant)
    {
        byte[] d = Encodings.FromBase64(base64, variant);
        
        Assert.AreEqual(data, Encoding.UTF8.GetString(d));
    }
    
    [TestMethod]
    [DataRow(null, Encodings.Base64Variant.Original)]
    [DataRow("", Encodings.Base64Variant.Original)]
    // https://eprint.iacr.org/2022/361
    [DataRow("SGVsbG9=", Encodings.Base64Variant.Original)]
    [DataRow("SGVsbG9", Encodings.Base64Variant.Original)]
    [DataRow("SGVsbA=", Encodings.Base64Variant.Original)]
    [DataRow("SGVsbA", Encodings.Base64Variant.Original)]
    [DataRow("SGVsbA====", Encodings.Base64Variant.Original)]
    // https://base64.guru/standards/base64url
    [DataRow("PDw_Pz8-Pg==", Encodings.Base64Variant.Original)]
    [DataRow("PDw/Pz8+Pg", Encodings.Base64Variant.Original)]
    [DataRow("PDw_Pz8-Pg", Encodings.Base64Variant.OriginalNoPadding)]
    [DataRow("PDw/Pz8+Pg==", Encodings.Base64Variant.OriginalNoPadding)]
    [DataRow("PDw/Pz8+Pg==", Encodings.Base64Variant.Url)]
    [DataRow("PDw_Pz8-Pg", Encodings.Base64Variant.Url)]
    [DataRow("PDw/Pz8+Pg", Encodings.Base64Variant.UrlNoPadding)]
    [DataRow("PDw_Pz8-Pg==", Encodings.Base64Variant.UrlNoPadding)]
    public void FromBase64_Invalid(string base64, Encodings.Base64Variant variant)
    {
        if (base64 == null) {
            Assert.ThrowsException<ArgumentNullException>(() => Encodings.FromBase64(base64, variant));
        }
        else if (base64 == "") {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => Encodings.FromBase64(base64, variant));
        }
        else {
            Assert.ThrowsException<FormatException>(() => Encodings.FromBase64(base64, variant));
        }
    }
}