namespace Geralt.Tests;

[TestClass]
public class AEGIS256Tests
{
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead#appendix-A.3
    public static IEnumerable<object[]> InternetDraftTestVectors()
    {
        yield return new object[]
        {
            "754fc3d8c973246dcc6d741412a4b2361181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13",
            "00000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        };
        yield return new object[]
        {
            "6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a",
            "",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        };
        yield return new object[]
        {
            "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607"
        };
        yield return new object[]
        {
            "f373079ed84b2709faee373584588c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
            "000102030405060708090a0b0c0d",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607"
        };
        yield return new object[]
        {
            "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { AEGIS256.TagSize, 1, AEGIS256.NonceSize, AEGIS256.KeySize, AEGIS256.TagSize };
        yield return new object[] { AEGIS256.TagSize, 0, AEGIS256.NonceSize + 1, AEGIS256.KeySize, AEGIS256.TagSize };
        yield return new object[] { AEGIS256.TagSize, 0, AEGIS256.NonceSize - 1, AEGIS256.KeySize, AEGIS256.TagSize };
        yield return new object[] { AEGIS256.TagSize, 0, AEGIS256.NonceSize, AEGIS256.KeySize + 1, AEGIS256.TagSize };
        yield return new object[] { AEGIS256.TagSize, 0, AEGIS256.NonceSize, AEGIS256.KeySize - 1, AEGIS256.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, AEGIS256.KeySize);
        Assert.AreEqual(32, AEGIS256.NonceSize);
        Assert.AreEqual(32, AEGIS256.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(InternetDraftTestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        AEGIS256.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS256.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(InternetDraftTestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        AEGIS256.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InternetDraftTestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };

        foreach (var param in parameters.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => AEGIS256.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS256.Decrypt(p, c, n, k, ad));
    }
}
