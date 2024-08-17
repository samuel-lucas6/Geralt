namespace Geralt.Tests;

[TestClass]
public class XChaCha20Tests
{
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.3.1
    public static IEnumerable<object[]> InternetDraftFillTestVectors()
    {
        yield return new object[]
        {
            "7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        };
    }

    public static IEnumerable<object[]> FillInvalidParameterSizes()
    {
        yield return new object[] { 0, XChaCha20.NonceSize, XChaCha20.KeySize };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.NonceSize + 1, XChaCha20.KeySize };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.NonceSize - 1, XChaCha20.KeySize };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.NonceSize, XChaCha20.KeySize + 1 };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.NonceSize, XChaCha20.KeySize - 1 };
    }

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.3.2
    public static IEnumerable<object[]> InternetDraftEncryptTestVectors()
    {
        yield return new object[]
        {
            "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f5051525354555658",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (ulong)0
        };
        yield return new object[]
        {
            "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee053a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd20112f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d316838a9c71f70b5b5907a66f7ea49aadc409",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f5051525354555658",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (ulong)1
        };
    }

    public static IEnumerable<object[]> EncryptInvalidParameterSizes()
    {
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.BlockSize + 1, XChaCha20.NonceSize, XChaCha20.KeySize, (ulong)0 };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.BlockSize - 1, XChaCha20.NonceSize, XChaCha20.KeySize, (ulong)0 };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.BlockSize, XChaCha20.NonceSize + 1, XChaCha20.KeySize, (ulong)0 };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.BlockSize, XChaCha20.NonceSize - 1, XChaCha20.KeySize, (ulong)0 };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.BlockSize, XChaCha20.NonceSize, XChaCha20.KeySize + 1, (ulong)0 };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.BlockSize, XChaCha20.NonceSize, XChaCha20.KeySize - 1, (ulong)0 };
        yield return new object[] { XChaCha20.BlockSize, XChaCha20.BlockSize, XChaCha20.NonceSize, XChaCha20.KeySize, ulong.MaxValue };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, XChaCha20.KeySize);
        Assert.AreEqual(24, XChaCha20.NonceSize);
        Assert.AreEqual(64, XChaCha20.BlockSize);
    }

    [TestMethod]
    [DynamicData(nameof(InternetDraftFillTestVectors), DynamicDataSourceType.Method)]
    public void Fill_Valid(string buffer, string nonce, string key)
    {
        Span<byte> b = stackalloc byte[buffer.Length / 2];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        XChaCha20.Fill(b, n, k);

        Assert.AreEqual(buffer, Convert.ToHexString(b).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(FillInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Fill_Invalid(int bufferSize, int nonceSize, int keySize)
    {
        var b = new byte[bufferSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20.Fill(b, n, k));
    }

    [TestMethod]
    [DynamicData(nameof(InternetDraftEncryptTestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, ulong counter)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        XChaCha20.Encrypt(c, p, n, k, counter);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, ulong counter)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        if (counter < ulong.MaxValue) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20.Encrypt(c, p, n, k, counter));
        }
        else {
            Assert.ThrowsException<CryptographicException>(() => XChaCha20.Encrypt(c, p, n, k, counter));
        }
    }

    [TestMethod]
    [DynamicData(nameof(InternetDraftEncryptTestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, ulong counter)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        XChaCha20.Decrypt(p, c, n, k, counter);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(EncryptInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, ulong counter)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        if (counter < ulong.MaxValue) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20.Decrypt(p, c, n, k, counter));
        }
        else {
            Assert.ThrowsException<CryptographicException>(() => XChaCha20.Decrypt(p, c, n, k, counter));
        }
    }
}
