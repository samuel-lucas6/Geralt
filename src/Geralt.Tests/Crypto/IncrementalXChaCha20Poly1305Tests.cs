namespace Geralt.Tests;

[TestClass]
public class IncrementalXChaCha20Poly1305Tests
{
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

    public static IEnumerable<object[]> IncrementalInvalidParameterSizes()
    {
        yield return [IncrementalXChaCha20Poly1305.HeaderSize + 1, IncrementalXChaCha20Poly1305.KeySize, IncrementalXChaCha20Poly1305.TagSize, 0];
        yield return [IncrementalXChaCha20Poly1305.HeaderSize - 1, IncrementalXChaCha20Poly1305.KeySize, IncrementalXChaCha20Poly1305.TagSize, 0];
        yield return [IncrementalXChaCha20Poly1305.HeaderSize, IncrementalXChaCha20Poly1305.KeySize + 1, IncrementalXChaCha20Poly1305.TagSize, 0];
        yield return [IncrementalXChaCha20Poly1305.HeaderSize, IncrementalXChaCha20Poly1305.KeySize - 1, IncrementalXChaCha20Poly1305.TagSize, 0];
        yield return [IncrementalXChaCha20Poly1305.HeaderSize, IncrementalXChaCha20Poly1305.KeySize, IncrementalXChaCha20Poly1305.TagSize, 1];
    }

    [TestMethod]
    public void Incremental_Constants_Valid()
    {
        Assert.AreEqual(32, IncrementalXChaCha20Poly1305.KeySize);
        Assert.AreEqual(24, IncrementalXChaCha20Poly1305.HeaderSize);
        Assert.AreEqual(17, IncrementalXChaCha20Poly1305.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(IncrementalEncryptParameters), DynamicDataSourceType.Method)]
    public void Incremental_Valid(string key, string plaintext, string associatedData)
    {
        Span<byte> h = stackalloc byte[IncrementalXChaCha20Poly1305.HeaderSize];
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + IncrementalXChaCha20Poly1305.TagSize];

        using var encryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: true);
        encryptor.EncryptChunk(c, p, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        p.Clear();

        using var decryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: false);
        var chunkFlag = decryptor.DecryptChunk(p, c);

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

        using var encryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: true);
        encryptor.EncryptChunk(c, p, ad, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        p.Clear();

        using var decryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: false);
        var chunkFlag = decryptor.DecryptChunk(p, c, ad);

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

        using var encryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: true);
        encryptor.EncryptChunk(c1, p1, IncrementalXChaCha20Poly1305.ChunkFlag.Message);
        encryptor.Rekey();
        encryptor.EncryptChunk(c2, p2, IncrementalXChaCha20Poly1305.ChunkFlag.Boundary);
        encryptor.EncryptChunk(c3, p3, IncrementalXChaCha20Poly1305.ChunkFlag.Rekey);
        encryptor.EncryptChunk(c4, p4, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        p1.Clear(); p2.Clear(); p3.Clear(); p4.Clear();

        using var decryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: false);
        var chunkFlag = decryptor.DecryptChunk(p1, c1);
        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Message, chunkFlag);

        decryptor.Rekey();

        chunkFlag = decryptor.DecryptChunk(p2, c2);
        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Boundary, chunkFlag);

        chunkFlag = decryptor.DecryptChunk(p3, c3);
        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Rekey, chunkFlag);

        chunkFlag = decryptor.DecryptChunk(p4, c4);
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

        using var secretstream = new IncrementalXChaCha20Poly1305(h, k, encryption: true);
        secretstream.EncryptChunk(c, p, IncrementalXChaCha20Poly1305.ChunkFlag.Final);

        secretstream.Reinitialize(h, k, encryption: true);
        secretstream.EncryptChunk(c, p, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        p.Clear();

        secretstream.Reinitialize(h, k, encryption: false);
        var chunkFlag = secretstream.DecryptChunk(p, c);

        Assert.AreEqual(IncrementalXChaCha20Poly1305.ChunkFlag.Final, chunkFlag);
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(IncrementalDecryptTestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Tampered(string header, string key, string plaintext, string ciphertext, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "h", Convert.FromHexString(header) },
            { "k", Convert.FromHexString(key) },
            { "c", Convert.FromHexString(ciphertext) },
            { "ad", Convert.FromHexString(associatedData) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            using var decryptor = new IncrementalXChaCha20Poly1305(parameters["h"], parameters["k"], encryption: false);
            Assert.ThrowsExactly<CryptographicException>(() => decryptor.DecryptChunk(p, parameters["c"], parameters["ad"]));
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

        using var decryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: false);
        // Should rekey here
        Assert.ThrowsExactly<CryptographicException>(() => decryptor.DecryptChunk(p, c));
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
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new IncrementalXChaCha20Poly1305(h, k, encryption: true));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new IncrementalXChaCha20Poly1305(h, k, encryption: false));
        }
        else {
            using var encryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: true);
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => encryptor.EncryptChunk(c, p));

            using var decryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: false);
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => decryptor.DecryptChunk(p, c));
        }
    }

    [TestMethod]
    public void Incremental_InvalidOperation()
    {
        Span<byte> h = stackalloc byte[IncrementalXChaCha20Poly1305.HeaderSize];
        Span<byte> k = stackalloc byte[IncrementalXChaCha20Poly1305.KeySize];
        var p = new byte[h.Length];
        var c = new byte[p.Length + IncrementalXChaCha20Poly1305.TagSize];

        using var encryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: true);
        Assert.ThrowsExactly<InvalidOperationException>(() => encryptor.DecryptChunk(p, c));
        encryptor.EncryptChunk(c, p, IncrementalXChaCha20Poly1305.ChunkFlag.Final);
        Assert.ThrowsExactly<InvalidOperationException>(() => encryptor.EncryptChunk(c, p));

        using var decryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: false);
        Assert.ThrowsExactly<InvalidOperationException>(() => decryptor.EncryptChunk(c, p));
        decryptor.DecryptChunk(p, c);
        Assert.ThrowsExactly<InvalidOperationException>(() => decryptor.DecryptChunk(p, c));
    }

    [TestMethod]
    public void Incremental_Disposed()
    {
        var h = new byte[IncrementalXChaCha20Poly1305.HeaderSize];
        var k = new byte[IncrementalXChaCha20Poly1305.KeySize];
        var p = new byte[h.Length];
        var c = new byte[p.Length + IncrementalXChaCha20Poly1305.TagSize];

        var encryptor = new IncrementalXChaCha20Poly1305(h, k, encryption: true);

        encryptor.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => encryptor.Reinitialize(h, k, encryption: false));
        Assert.ThrowsExactly<ObjectDisposedException>(() => encryptor.EncryptChunk(c, p, IncrementalXChaCha20Poly1305.ChunkFlag.Final));
        Assert.ThrowsExactly<ObjectDisposedException>(() => encryptor.DecryptChunk(p, c));
        Assert.ThrowsExactly<ObjectDisposedException>(() => encryptor.Rekey());
    }
}
