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

    public static IEnumerable<object[]> IncrementalEncryptParameters()
    {
        yield return
        [
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "0421d1d53971008907219aa2e371102a1f722a42b761a7eaf1d48a972f680bd27ea5c45efb51b91a7a7a4cd0de23b32d70ea706fee3d2ef6a64d8f44d996e164",
            "50515253c0c1c2c3c4c5c6c7"
        ];
    }

    public static IEnumerable<object[]> IncrementalDecryptTestVectors()
    {
        yield return
        [
            "d08a6b1c74e2ffbf158eef1ba3fb42b48a9a2c49bbc6255b",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "23eb1e60c81fcc46aaf0f5321786a970473801a348a673a18928378c324254a075f201efb219c134c17daca9769a6fdee4dc72da0107f35a3ced05f7cad103d79a06d26cf29c457b72cd0fa79ed39ce381d14c2dcc5b56e45a1f626eb68f2eae8dcf08eee8c24049bea3822cb835f30e929310bb33ba6eb383bdd8e12ebba1074ea52a",
            "50515253c0c1c2c3c4c5c6c7"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [XChaCha20Poly1305.TagSize, 1, XChaCha20Poly1305.NonceSize, XChaCha20Poly1305.KeySize, XChaCha20Poly1305.TagSize];
        yield return [XChaCha20Poly1305.TagSize, 0, XChaCha20Poly1305.NonceSize + 1, XChaCha20Poly1305.KeySize, XChaCha20Poly1305.TagSize];
        yield return [XChaCha20Poly1305.TagSize, 0, XChaCha20Poly1305.NonceSize - 1, XChaCha20Poly1305.KeySize, XChaCha20Poly1305.TagSize];
        yield return [XChaCha20Poly1305.TagSize, 0, XChaCha20Poly1305.NonceSize, XChaCha20Poly1305.KeySize + 1, XChaCha20Poly1305.TagSize];
        yield return [XChaCha20Poly1305.TagSize, 0, XChaCha20Poly1305.NonceSize, XChaCha20Poly1305.KeySize - 1, XChaCha20Poly1305.TagSize];
    }

    public static IEnumerable<object[]> IncrementalInvalidParameterSizes()
    {
        yield return [IncrementalXChaCha20Poly1305.HeaderSize + 1, IncrementalXChaCha20Poly1305.KeySize, IncrementalXChaCha20Poly1305.TagSize, 0];
        yield return [IncrementalXChaCha20Poly1305.HeaderSize - 1, IncrementalXChaCha20Poly1305.KeySize, IncrementalXChaCha20Poly1305.TagSize, 0];
        yield return [IncrementalXChaCha20Poly1305.HeaderSize, IncrementalXChaCha20Poly1305.KeySize + 1, IncrementalXChaCha20Poly1305.TagSize, 0];
        yield return [IncrementalXChaCha20Poly1305.HeaderSize, IncrementalXChaCha20Poly1305.KeySize - 1, IncrementalXChaCha20Poly1305.TagSize, 0];
        yield return [IncrementalXChaCha20Poly1305.HeaderSize, IncrementalXChaCha20Poly1305.KeySize, IncrementalXChaCha20Poly1305.TagSize, 1];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, XChaCha20Poly1305.KeySize);
        Assert.AreEqual(24, XChaCha20Poly1305.NonceSize);
        Assert.AreEqual(16, XChaCha20Poly1305.TagSize);
    }

    [TestMethod]
    public void Incremental_Constants_Valid()
    {
        Assert.AreEqual(32, IncrementalXChaCha20Poly1305.KeySize);
        Assert.AreEqual(24, IncrementalXChaCha20Poly1305.HeaderSize);
        Assert.AreEqual(17, IncrementalXChaCha20Poly1305.TagSize);
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

        XChaCha20Poly1305.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Encrypt(c, p, n, k, ad));
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

        XChaCha20Poly1305.Decrypt(p, c, n, k, ad);

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

        foreach (var param in parameters) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => XChaCha20Poly1305.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XChaCha20Poly1305.Decrypt(p, c, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(IncrementalEncryptParameters), DynamicDataSourceType.Method)]
    public void Incremental_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[IncrementalXChaCha20Poly1305.HeaderSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + IncrementalXChaCha20Poly1305.TagSize];

        using var encryptor = new IncrementalXChaCha20Poly1305(decryption: false, h, k);
        encryptor.Push(c, p, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        p.Clear();

        using var decryptor = new IncrementalXChaCha20Poly1305(decryption: true, h, k);
        var chunkFlag = decryptor.Pull(p, c);

        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Final, chunkFlag);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(IncrementalEncryptParameters), DynamicDataSourceType.Method)]
    public void Incremental_AssociatedData_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[IncrementalXChaCha20Poly1305.HeaderSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> ad = Convert.FromHexString(associatedData);
        Span<byte> c = stackalloc byte[p.Length + IncrementalXChaCha20Poly1305.TagSize];

        using var encryptor = new IncrementalXChaCha20Poly1305(decryption: false, h, k);
        encryptor.Push(c, p, ad, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        p.Clear();

        using var decryptor = new IncrementalXChaCha20Poly1305(decryption: true, h, k);
        var chunkFlag = decryptor.Pull(p, c, ad);

        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Final, chunkFlag);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(IncrementalEncryptParameters), DynamicDataSourceType.Method)]
    public void Incremental_Chunked_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[IncrementalXChaCha20Poly1305.HeaderSize];
        Span<byte> k = Convert.FromHexString(key);

        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> p1 = p[..16], p2 = p[16..32], p3 = p[32..48], p4 = p[48..];

        Span<byte> c = stackalloc byte[p.Length + IncrementalXChaCha20Poly1305.TagSize * 4];
        Span<byte> c1 = c[..33], c2 = c[33..66], c3 = c[66..99], c4 = c[99..];

        using var encryptor = new IncrementalXChaCha20Poly1305(decryption: false, h, k);
        encryptor.Push(c1, p1, IncrementalXChaCha20Poly1305.ChunkFlag.Message);
        encryptor.Rekey();
        encryptor.Push(c2, p2, IncrementalXChaCha20Poly1305.ChunkFlag.Boundary);
        encryptor.Push(c3, p3, IncrementalXChaCha20Poly1305.ChunkFlag.Rekey);
        encryptor.Push(c4, p4, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        p1.Clear(); p2.Clear(); p3.Clear(); p4.Clear();

        using var decryptor = new IncrementalXChaCha20Poly1305(decryption: true, h, k);
        var chunkFlag = decryptor.Pull(p1, c1);
        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Message, chunkFlag);

        decryptor.Rekey();

        chunkFlag = decryptor.Pull(p2, c2);
        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Boundary, chunkFlag);

        chunkFlag = decryptor.Pull(p3, c3);
        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Rekey, chunkFlag);

        chunkFlag = decryptor.Pull(p4, c4);
        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Final, chunkFlag);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(IncrementalEncryptParameters), DynamicDataSourceType.Method)]
    public void Incremental_Reinitialize_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[IncrementalXChaCha20Poly1305.HeaderSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + IncrementalXChaCha20Poly1305.TagSize];

        using var secretstream = new IncrementalXChaCha20Poly1305(decryption: false, h, k);
        secretstream.Push(c, p, IncrementalXChaCha20Poly1305.ChunkFlag.Final);

        secretstream.Reinitialize(decryption: false, h, k);
        secretstream.Push(c, p, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        p.Clear();

        secretstream.Reinitialize(decryption: true, h, k);
        var chunkFlag = secretstream.Pull(p, c);

        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Final, chunkFlag);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(IncrementalInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Incremental_Invalid(int headerSize, int keySize, int ciphertextSize, int plaintextSize)
    {
        var h = new byte[headerSize];
        var k = new byte[keySize];
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];

        if (headerSize != IncrementalXChaCha20Poly1305.HeaderSize || keySize != IncrementalXChaCha20Poly1305.KeySize) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new IncrementalXChaCha20Poly1305(decryption: false, h, k));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new IncrementalXChaCha20Poly1305(decryption: true, h, k));
        }
        else {
            using var encryptor = new IncrementalXChaCha20Poly1305(decryption: false, h, k);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => encryptor.Push(c, p));

            using var decryptor = new IncrementalXChaCha20Poly1305(decryption: true, h, k);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => decryptor.Pull(p, c));
        }
    }

    [TestMethod]
    public void Incremental_InvalidOperation()
    {
        Span<byte> h = stackalloc byte[IncrementalXChaCha20Poly1305.HeaderSize];
        Span<byte> k = stackalloc byte[IncrementalXChaCha20Poly1305.KeySize];
        var p = new byte[h.Length];
        var c = new byte[p.Length + IncrementalXChaCha20Poly1305.TagSize];

        using var encryptor = new IncrementalXChaCha20Poly1305(decryption: false, h, k);
        Assert.ThrowsException<InvalidOperationException>(() => encryptor.Pull(p, c));
        encryptor.Push(c, p, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        Assert.ThrowsException<InvalidOperationException>(() => encryptor.Push(c, p));

        using var decryptor = new IncrementalXChaCha20Poly1305(decryption: true, h, k);
        Assert.ThrowsException<InvalidOperationException>(() => decryptor.Push(c, p));
        decryptor.Pull(p, c);
        Assert.ThrowsException<InvalidOperationException>(() => decryptor.Pull(p, c));
    }

    [TestMethod]
    [DynamicData(nameof(IncrementalDecryptTestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Tampered(string header, string key, string plaintext, string ciphertext, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(header),
            Convert.FromHexString(key),
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(associatedData)
        };

        foreach (var param in parameters) {
            param[0]++;
            using var decryptor = new IncrementalXChaCha20Poly1305(decryption: true, parameters[0], parameters[1]);
            Assert.ThrowsException<CryptographicException>(() => decryptor.Pull(p, parameters[2], parameters[3]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DataRow("3677e196fb57f611fe71cf25cbd892481f7a7179c2827102", "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e", "cc55781c4cb5443c19b856b695a2a6fc801935832c9c8278da67de429c3760231c846838d5a58a89815a99d572bfcf6ec14ed725931c6ac1fb7445eb25cad39773502f9550670fd918638c89d83ddfda7297b59281b6012f780c0b3f0cb6309345573c7967fbcfb8843ce04db7912754fe861f5963c83dc6ad066c0d04b3235ade74ca", "")]
    public void Incremental_MissingRekey(string header, string key, string plaintext, string ciphertext, string associatedData)
    {
        var h = Convert.FromHexString(header);
        var k = Convert.FromHexString(key);
        var p = new byte[plaintext.Length / 2];
        var c = Convert.FromHexString(ciphertext);

        using var decryptor = new IncrementalXChaCha20Poly1305(decryption: true, h, k);
        // Should rekey here
        Assert.ThrowsException<CryptographicException>(() => decryptor.Pull(p, c));
    }
}
