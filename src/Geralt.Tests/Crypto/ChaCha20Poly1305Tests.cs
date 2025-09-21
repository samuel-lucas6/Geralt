namespace Geralt.Tests;

[TestClass]
public class ChaCha20Poly1305Tests
{
    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    // https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.5
    public static IEnumerable<object[]> Rfc8439TestVectors()
    {
        yield return
        [
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        ];
        yield return
        [
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38",
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
            "000000000102030405060708",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "f33388860000000000004e91"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ChaCha20Poly1305.TagSize - 1, 0, ChaCha20Poly1305.NonceSize, ChaCha20Poly1305.KeySize, ChaCha20Poly1305.TagSize];
        yield return [ChaCha20Poly1305.TagSize, 1, ChaCha20Poly1305.NonceSize, ChaCha20Poly1305.KeySize, ChaCha20Poly1305.TagSize];
        yield return [ChaCha20Poly1305.TagSize, 0, ChaCha20Poly1305.NonceSize + 1, ChaCha20Poly1305.KeySize, ChaCha20Poly1305.TagSize];
        yield return [ChaCha20Poly1305.TagSize, 0, ChaCha20Poly1305.NonceSize - 1, ChaCha20Poly1305.KeySize, ChaCha20Poly1305.TagSize];
        yield return [ChaCha20Poly1305.TagSize, 0, ChaCha20Poly1305.NonceSize, ChaCha20Poly1305.KeySize + 1, ChaCha20Poly1305.TagSize];
        yield return [ChaCha20Poly1305.TagSize, 0, ChaCha20Poly1305.NonceSize, ChaCha20Poly1305.KeySize - 1, ChaCha20Poly1305.TagSize];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, ChaCha20Poly1305.KeySize);
        Assert.AreEqual(12, ChaCha20Poly1305.NonceSize);
        Assert.AreEqual(16, ChaCha20Poly1305.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        ChaCha20Poly1305.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        ChaCha20Poly1305.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(Rfc8439TestVectors), DynamicDataSourceType.Method)]
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
            Assert.ThrowsExactly<CryptographicException>(() => ChaCha20Poly1305.Decrypt(p, parameters["c"], parameters["n"], parameters["k"], parameters["ad"]));
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

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ChaCha20Poly1305.Decrypt(p, c, n, k, ad));
    }
}
