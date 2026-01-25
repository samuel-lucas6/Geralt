namespace Geralt.Tests;

[TestClass]
public class XChaCha20Poly1305Tests
{
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.3.1
    public static IEnumerable<object[]> InternetDraftTestVectors()
    {
        yield return
        [
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [XChaCha20Poly1305.TagSize - 1, 0, XChaCha20Poly1305.NonceSize, XChaCha20Poly1305.KeySize, XChaCha20Poly1305.TagSize];
        yield return [XChaCha20Poly1305.TagSize, 1, XChaCha20Poly1305.NonceSize, XChaCha20Poly1305.KeySize, XChaCha20Poly1305.TagSize];
        yield return [XChaCha20Poly1305.TagSize, 0, XChaCha20Poly1305.NonceSize + 1, XChaCha20Poly1305.KeySize, XChaCha20Poly1305.TagSize];
        yield return [XChaCha20Poly1305.TagSize, 0, XChaCha20Poly1305.NonceSize - 1, XChaCha20Poly1305.KeySize, XChaCha20Poly1305.TagSize];
        yield return [XChaCha20Poly1305.TagSize, 0, XChaCha20Poly1305.NonceSize, XChaCha20Poly1305.KeySize + 1, XChaCha20Poly1305.TagSize];
        yield return [XChaCha20Poly1305.TagSize, 0, XChaCha20Poly1305.NonceSize, XChaCha20Poly1305.KeySize - 1, XChaCha20Poly1305.TagSize];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, XChaCha20Poly1305.KeySize);
        Assert.AreEqual(24, XChaCha20Poly1305.NonceSize);
        Assert.AreEqual(16, XChaCha20Poly1305.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(InternetDraftTestVectors))]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        XChaCha20Poly1305.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes))]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(InternetDraftTestVectors))]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        XChaCha20Poly1305.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InternetDraftTestVectors))]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "c", Convert.FromHexString(ciphertext) },
            { "n", Convert.FromHexString(nonce) },
            { "k", Convert.FromHexString(key) },
            { "ad", Convert.FromHexString(associatedData) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsExactly<CryptographicException>(() => XChaCha20Poly1305.Decrypt(p, parameters["c"], parameters["n"], parameters["k"], parameters["ad"]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes))]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Decrypt(p, c, n, k, ad));
    }
}
