namespace Geralt.Tests;

[TestClass]
public class EncodingsTests
{
    // https://www.rfc-editor.org/rfc/rfc4648#section-10
    public static IEnumerable<object[]> Rfc4648HexTestVectors()
    {
        yield return ["66", "f"];
        yield return ["666f", "fo"];
        yield return ["666f6f", "foo"];
        yield return ["666f6f62", "foob"];
        yield return ["666f6f6261", "fooba"];
        yield return ["666f6f626172", "foobar"];
    }

    // https://www.rfc-editor.org/rfc/rfc4648#section-10
    public static IEnumerable<object[]> Rfc4648Base64TestVectors()
    {
        yield return ["Zg==", "f", Encodings.Base64Variant.Original];
        yield return ["Zm8=", "fo", Encodings.Base64Variant.Original];
        yield return ["Zm9v", "foo", Encodings.Base64Variant.Original];
        yield return ["Zm9vYg==", "foob", Encodings.Base64Variant.Original];
        yield return ["Zm9vYmE=", "fooba", Encodings.Base64Variant.Original];
        yield return ["Zm9vYmFy", "foobar", Encodings.Base64Variant.Original];
    }

    // https://eprint.iacr.org/2022/361
    // https://base64.guru/standards/base64url
    public static IEnumerable<object[]> Base64VariantTestVectors()
    {
        yield return ["SGVsbG8=", "Hello", Encodings.Base64Variant.Original];
        yield return ["SGVsbA==", "Hell", Encodings.Base64Variant.Original];
        yield return ["PDw/Pz8+Pg", "<<???>>", Encodings.Base64Variant.OriginalNoPadding];
        yield return ["PDw_Pz8-Pg==", "<<???>>", Encodings.Base64Variant.Url];
        yield return ["PDw_Pz8-Pg", "<<???>>", Encodings.Base64Variant.UrlNoPadding];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual("0123456789ABCDEFabcdef", Encodings.HexCharacterSet);
        Assert.AreEqual("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", Encodings.Base64CharacterSet);
        Assert.AreEqual("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=", Encodings.Base64UrlCharacterSet);
        Assert.AreEqual("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=", Encodings.Base64FullCharacterSet);
        Assert.AreEqual(":- ./,", Encodings.HexIgnoreChars);
        Assert.AreEqual(" \r\n", Encodings.Base64IgnoreChars);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc4648HexTestVectors), DynamicDataSourceType.Method)]
    public void ToHex_Valid(string hex, string data)
    {
        Span<byte> d = Encoding.UTF8.GetBytes(data);
        Span<char> h = stackalloc char[Encodings.GetToHexBufferSize(d)];

        Encodings.ToHex(h, d);

        Assert.AreEqual(hex, h.ToString());
    }

    [TestMethod]
    [DataRow(0, 1)]
    [DataRow(1, 0)]
    [DataRow(2 + 1, 1)]
    [DataRow(2 - 1, 1)]
    public void ToHex_Invalid(int hexSize, int dataSize)
    {
        var h = new char[hexSize];
        var d = new byte[dataSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Encodings.ToHex(h, d));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc4648HexTestVectors), DynamicDataSourceType.Method)]
    [DataRow("66", "f", Encodings.HexIgnoreChars)]
    [DataRow("666F6F", "foo", "")]
    [DataRow("66 6f 6f 62", "foob", " ")]
    [DataRow("66:6f:6f:62:61", "fooba", ":")]
    [DataRow("66 : 6f : 6f : 62 : 61 : 72", "foobar", ": ")]
    public void FromHex_Valid(string hex, string data, string? ignoreChars = null)
    {
        Span<byte> d = stackalloc byte[Encodings.GetFromHexBufferSize(hex, ignoreChars)];

        Encodings.FromHex(d, hex, ignoreChars);

        Assert.AreEqual(data, Encoding.UTF8.GetString(d));
    }

    [TestMethod]
    [DataRow(1, "Zg", "")]
    [DataRow(2, "Zg==", "")]
    [DataRow(5, "PDw/Pz8+Pg", "")]
    [DataRow(4, "66/6f/6f", "")]
    [DataRow(4, "66/6f/6f", ":")]
    public void FromHex_Tampered(int dataSize, string hex, string ignoreChars)
    {
        var d = new byte[dataSize];

        Assert.ThrowsExactly<FormatException>(() => Encodings.FromHex(d, hex, ignoreChars));
    }

    [TestMethod]
    [DataRow(0, null, "")]
    [DataRow(0, "", "")]
    [DataRow(0, null, ":")]
    [DataRow(0, "", ":")]
    [DataRow(2, "zzz", "")]
    [DataRow(2, "zzz", ":")]
    [DataRow(2, "666f", "a")]
    [DataRow(2, "666f", "A")]
    [DataRow(2, "666f", "f")]
    [DataRow(2, "666f", "F")]
    [DataRow(2, "666f", "0")]
    [DataRow(2, "666f", "9")]
    [DataRow(2, "Zg==", "Zg=")]
    [DataRow(4, "66/6f/6f", "/")]
    public void FromHex_Invalid(int dataSize, string? hex, string ignoreChars)
    {
        var d = new byte[dataSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Encodings.FromHex(d, hex, ignoreChars));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc4648Base64TestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(Base64VariantTestVectors), DynamicDataSourceType.Method)]
    public void ToBase64_Valid(string base64, string data, Encodings.Base64Variant variant)
    {
        Span<byte> d = Encoding.UTF8.GetBytes(data);
        Span<char> b = stackalloc char[Encodings.GetToBase64BufferSize(d, variant)];

        Encodings.ToBase64(b, d, variant);

        Assert.AreEqual(base64, b.ToString());
    }

    [TestMethod]
    [DataRow(0, 1)]
    [DataRow(1, 0)]
    [DataRow(4 + 1, 3)]
    [DataRow(4 - 1, 3)]
    public void ToBase64_Invalid(int base64Size, int dataSize)
    {
        var b = new char[base64Size];
        var d = new byte[dataSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Encodings.ToBase64(b, d));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc4648Base64TestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(Base64VariantTestVectors), DynamicDataSourceType.Method)]
    [DataRow("Z g = =", "f", Encodings.Base64Variant.Original, " ")]
    [DataRow("Zg= =\r", "f", Encodings.Base64Variant.Original, " \r")]
    [DataRow("Zg= =\n", "f", Encodings.Base64Variant.Original, " \n")]
    [DataRow("Zg= =\r\n", "f", Encodings.Base64Variant.Original, Encodings.Base64IgnoreChars)]
    public void FromBase64_Valid(string base64, string data, Encodings.Base64Variant variant, string? ignoreChars = null)
    {
        Span<byte> d = stackalloc byte[Encodings.GetFromBase64BufferSize(base64, variant, ignoreChars)];

        Encodings.FromBase64(d, base64, variant, ignoreChars);

        Assert.AreEqual(data, Encoding.UTF8.GetString(d));
    }

    [TestMethod]
    // https://eprint.iacr.org/2022/361
    [DataRow("SGVsbG9=", Encodings.Base64Variant.Original)]
    [DataRow("SGVsbG9", Encodings.Base64Variant.Original)]
    [DataRow("SGVsbA=", Encodings.Base64Variant.Original)]
    [DataRow("SGVsbA", Encodings.Base64Variant.Original)]
    [DataRow("SGVsbA====", Encodings.Base64Variant.Original)]
    // https://base64.guru/standards/base64url
    [DataRow("PDw_Pz8-Pg", Encodings.Base64Variant.Original)]
    [DataRow("PDw_Pz8-Pg=", Encodings.Base64Variant.Original)]
    [DataRow("PDw_Pz8-Pg==", Encodings.Base64Variant.Original)]
    [DataRow("PDw/Pz8+Pg", Encodings.Base64Variant.Original)]
    [DataRow("PDw/Pz8+Pg=", Encodings.Base64Variant.Original)]
    [DataRow("PDw/Pz8+Pg===", Encodings.Base64Variant.Original)]
    [DataRow("PDw_Pz8-Pg", Encodings.Base64Variant.OriginalNoPadding)]
    [DataRow("PDw_Pz8-Pg=", Encodings.Base64Variant.OriginalNoPadding)]
    [DataRow("PDw_Pz8-Pg==", Encodings.Base64Variant.OriginalNoPadding)]
    [DataRow("PDw/Pz8+Pg=", Encodings.Base64Variant.OriginalNoPadding)]
    [DataRow("PDw/Pz8+Pg==", Encodings.Base64Variant.OriginalNoPadding)]
    [DataRow("PDw_Pz8-Pg", Encodings.Base64Variant.Url)]
    [DataRow("PDw_Pz8-Pg=", Encodings.Base64Variant.Url)]
    [DataRow("PDw_Pz8-Pg===", Encodings.Base64Variant.Url)]
    [DataRow("PDw/Pz8+Pg", Encodings.Base64Variant.Url)]
    [DataRow("PDw/Pz8+Pg=", Encodings.Base64Variant.Url)]
    [DataRow("PDw/Pz8+Pg==", Encodings.Base64Variant.Url)]
    [DataRow("PDw_Pz8-Pg=", Encodings.Base64Variant.UrlNoPadding)]
    [DataRow("PDw_Pz8-Pg==", Encodings.Base64Variant.UrlNoPadding)]
    [DataRow("PDw/Pz8+Pg", Encodings.Base64Variant.UrlNoPadding)]
    [DataRow("PDw/Pz8+Pg=", Encodings.Base64Variant.UrlNoPadding)]
    [DataRow("PDw/Pz8+Pg==", Encodings.Base64Variant.UrlNoPadding)]
    public void FromBase64_Tampered(string? base64, Encodings.Base64Variant variant)
    {
        var d = new byte[Encodings.GetFromBase64BufferSize(base64, variant)];

        Assert.ThrowsExactly<FormatException>(() => Encodings.FromBase64(d, base64, variant));
    }

    [TestMethod]
    [DataRow(1, null, Encodings.Base64Variant.Original, "")]
    [DataRow(1, "", Encodings.Base64Variant.Original, "")]
    [DataRow(1 + 1, "Zg==", Encodings.Base64Variant.Original, "")]
    [DataRow(1 - 1, "Zg==", Encodings.Base64Variant.Original, "")]
    [DataRow(1, "Zg==", Encodings.Base64Variant.Original, "a")]
    [DataRow(1, "Zg==", Encodings.Base64Variant.Original, "Z")]
    [DataRow(1, "Zg==", Encodings.Base64Variant.Original, "=")]
    [DataRow(1, "Zg==", Encodings.Base64Variant.Original, "/")]
    [DataRow(1, "Zg==", Encodings.Base64Variant.Original, "_")]
    [DataRow(1, "!", Encodings.Base64Variant.Original, "!")]
    public void FromBase64_Invalid(int dataSize, string? base64, Encodings.Base64Variant variant, string? ignoreChars)
    {
        var d = new byte[dataSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Encodings.FromBase64(d, base64, variant, ignoreChars));
    }
}
