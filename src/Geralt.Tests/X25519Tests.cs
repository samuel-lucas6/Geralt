namespace Geralt.Tests;

[TestClass]
public class X25519Tests
{
    // https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
    public static IEnumerable<object[]> Rfc7748TestVectors()
    {
        yield return new object[]
        {
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        };
        yield return new object[]
        {
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        };
    }

    // https://github.com/google/wycheproof/blob/master/testvectors_v1/x25519_test.json
    public static IEnumerable<object[]> WycheproofTestVectors()
    {
        yield return new object[]
        {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "88227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd45e",
            "0000000000000000000000000000000000000000000000000000000000000000"
        };
        yield return new object[]
        {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "48232e8972b61c7e61930eb9450b5070eae1c670475685541f0476217e48184f",
            "0100000000000000000000000000000000000000000000000000000000000000"
        };
        yield return new object[]
        {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "e0f978dfcd3a8f1a5093418de54136a584c20b7b349afdf6c0520886f95b1272",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
        };
    }

    // https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
    public static IEnumerable<object[]> PublicKeyTestVectors()
    {
        yield return new object[]
        {
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        };
        yield return new object[]
        {
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        };
    }

    public static IEnumerable<object[]> DeriveSharedKeyTestVectors()
    {
        yield return new object[]
        {
            "519fb3af2f3f9e310718cf1f8bdec6e26ab64affe730f0f8b43c43b0e8ee52be",
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            ""
        };
        yield return new object[]
        {
            "a91209efc719601f61c54f74d369fe14f997a29a91b174d5771614b6c9407ad1",
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "5dbbfd1c5549181aa9319cd71b946757e1f4769aee9568bd360b651a86ea29a2"
        };
        yield return new object[]
        {
            "354447b415885c25326201b17a365be2d597ef75a95b6991d52d2e864c06a0ba",
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "871f4dcab454942a480381f59e34d3ed3cb0db4a70c575a984554c2af75b022aa02040644460daef8e64fe442e374be9b861ae142244412f76dbbb523f714eed"
        };
    }

    public static IEnumerable<object[]> KeyPairInvalidParameterSizes()
    {
        yield return new object[] { X25519.PublicKeySize + 1, X25519.PrivateKeySize };
        yield return new object[] { X25519.PublicKeySize - 1, X25519.PrivateKeySize };
        yield return new object[] { X25519.PublicKeySize, X25519.PrivateKeySize + 1 };
        yield return new object[] { X25519.PublicKeySize, X25519.PrivateKeySize - 1 };
    }

    public static IEnumerable<object[]> SharedKeyInvalidParameterSizes()
    {
        yield return new object[] { X25519.SharedKeySize + 1, X25519.PrivateKeySize, X25519.PublicKeySize, X25519.PreSharedKeySize };
        yield return new object[] { X25519.SharedKeySize - 1, X25519.PrivateKeySize, X25519.PublicKeySize, X25519.PreSharedKeySize };
        yield return new object[] { X25519.SharedKeySize, X25519.PrivateKeySize + 1, X25519.PublicKeySize, X25519.PreSharedKeySize };
        yield return new object[] { X25519.SharedKeySize, X25519.PrivateKeySize - 1, X25519.PublicKeySize, X25519.PreSharedKeySize };
        yield return new object[] { X25519.SharedKeySize, X25519.PrivateKeySize, X25519.PublicKeySize + 1, X25519.PreSharedKeySize };
        yield return new object[] { X25519.SharedKeySize, X25519.PrivateKeySize, X25519.PublicKeySize - 1, X25519.PreSharedKeySize };
        yield return new object[] { X25519.SharedKeySize, X25519.PrivateKeySize, X25519.PublicKeySize, X25519.MaxPreSharedKeySize + 1 };
        yield return new object[] { X25519.SharedKeySize, X25519.PrivateKeySize, X25519.PublicKeySize, X25519.MinPreSharedKeySize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, X25519.PublicKeySize);
        Assert.AreEqual(32, X25519.PrivateKeySize);
        Assert.AreEqual(32, X25519.SeedSize);
        Assert.AreEqual(32, X25519.SharedSecretSize);
        Assert.AreEqual(32, X25519.SharedKeySize);
        Assert.AreEqual(32, X25519.PreSharedKeySize);
        Assert.AreEqual(16, X25519.MinPreSharedKeySize);
        Assert.AreEqual(64, X25519.MaxPreSharedKeySize);
    }

    [TestMethod]
    public void GenerateKeyPair_Valid()
    {
        Span<byte> pk = stackalloc byte[X25519.PublicKeySize];
        Span<byte> sk = stackalloc byte[X25519.PrivateKeySize];

        X25519.GenerateKeyPair(pk, sk);

        Assert.IsFalse(pk.SequenceEqual(new byte[pk.Length]));
        Assert.IsFalse(sk.SequenceEqual(new byte[sk.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(KeyPairInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void GenerateKeyPair_Invalid(int publicKeySize, int privateKeySize)
    {
        var pk = new byte[publicKeySize];
        var sk = new byte[privateKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(pk, sk));
    }

    [TestMethod]
    [DataRow("10c84ef255d4682177b9d0b43d753552fbc6b0f2cf735e6b45cba18fa1f05444", "471cfd04edcbcb7f4174a88e9c9569b9aa9464254c3d5373ff6775cb22e7483f", "b589764bb6395e13788436f93f4eaa4c858900b6a12328e8626ded5b39d2c7e9")]
    public void GenerateKeyPairSeeded_Valid(string publicKey, string privateKey, string seed)
    {
        Span<byte> pk = stackalloc byte[X25519.PublicKeySize];
        Span<byte> sk = stackalloc byte[X25519.PrivateKeySize];
        Span<byte> s = Convert.FromHexString(seed);

        X25519.GenerateKeyPair(pk, sk, s);

        Assert.AreEqual(publicKey, Convert.ToHexString(pk).ToLower());
        Assert.AreEqual(privateKey, Convert.ToHexString(sk).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(KeyPairInvalidParameterSizes), DynamicDataSourceType.Method)]
    [DataRow(X25519.PublicKeySize, X25519.PrivateKeySize, X25519.SeedSize + 1)]
    [DataRow(X25519.PublicKeySize, X25519.PrivateKeySize, X25519.SeedSize - 1)]
    public void GenerateKeyPairSeeded_Invalid(int publicKeySize, int privateKeySize, int seedSize = X25519.SeedSize)
    {
        var pk = new byte[publicKeySize];
        var sk = new byte[privateKeySize];
        var s = new byte[seedSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.GenerateKeyPair(pk, sk, s));
    }

    [TestMethod]
    [DynamicData(nameof(PublicKeyTestVectors), DynamicDataSourceType.Method)]
    public void ComputePublicKey_Valid(string publicKey, string privateKey)
    {
        Span<byte> pk = stackalloc byte[X25519.PublicKeySize];
        Span<byte> sk = Convert.FromHexString(privateKey);

        X25519.ComputePublicKey(pk, sk);

        Assert.AreEqual(publicKey, Convert.ToHexString(pk).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(KeyPairInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ComputePublicKey_Invalid(int publicKeySize, int privateKeySize)
    {
        var pk = new byte[publicKeySize];
        var sk = new byte[privateKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputePublicKey(pk, sk));
    }

    [TestMethod]
    [DynamicData(nameof(Rfc7748TestVectors), DynamicDataSourceType.Method)]
    public void ComputeSharedSecret_Valid(string sharedSecret, string senderPrivateKey, string recipientPublicKey)
    {
        Span<byte> s = stackalloc byte[X25519.SharedSecretSize];
        Span<byte> sk = Convert.FromHexString(senderPrivateKey);
        Span<byte> pk = Convert.FromHexString(recipientPublicKey);

        X25519.ComputeSharedSecret(s, sk, pk);

        Assert.AreEqual(sharedSecret, Convert.ToHexString(s).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(WycheproofTestVectors), DynamicDataSourceType.Method)]
    public void ComputeSharedSecret_Tampered(string sharedSecret, string senderPrivateKey, string recipientPublicKey)
    {
        var s = new byte[X25519.SharedSecretSize];
        var sk = Convert.FromHexString(senderPrivateKey);
        var pk = Convert.FromHexString(recipientPublicKey);

        Assert.ThrowsException<CryptographicException>(() => X25519.ComputeSharedSecret(s, sk, pk));
    }

    [TestMethod]
    [DataRow(X25519.SharedSecretSize + 1, X25519.PrivateKeySize, X25519.PublicKeySize)]
    [DataRow(X25519.SharedSecretSize - 1, X25519.PrivateKeySize, X25519.PublicKeySize)]
    [DataRow(X25519.SharedSecretSize, X25519.PrivateKeySize + 1, X25519.PublicKeySize)]
    [DataRow(X25519.SharedSecretSize, X25519.PrivateKeySize - 1, X25519.PublicKeySize)]
    [DataRow(X25519.SharedSecretSize, X25519.PrivateKeySize, X25519.PublicKeySize + 1)]
    [DataRow(X25519.SharedSecretSize, X25519.PrivateKeySize, X25519.PublicKeySize - 1)]
    public void ComputeSharedSecret_Invalid(int sharedSecretSize, int senderPrivateKeySize, int recipientPublicKeySize)
    {
        var s = new byte[sharedSecretSize];
        var sk = new byte[senderPrivateKeySize];
        var pk = new byte[recipientPublicKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.ComputeSharedSecret(s, sk, pk));
    }

    [TestMethod]
    [DynamicData(nameof(DeriveSharedKeyTestVectors), DynamicDataSourceType.Method)]
    public void DeriveSharedKey_Valid(string sharedKey, string senderPrivateKey, string recipientPublicKey, string recipientPrivateKey, string senderPublicKey, string preSharedKey)
    {
        Span<byte> ss = stackalloc byte[X25519.SharedKeySize];
        Span<byte> ssk = Convert.FromHexString(senderPrivateKey);
        Span<byte> rpk = Convert.FromHexString(recipientPublicKey);
        Span<byte> rs = stackalloc byte[X25519.SharedKeySize];
        Span<byte> rsk = Convert.FromHexString(recipientPrivateKey);
        Span<byte> spk = Convert.FromHexString(senderPublicKey);
        Span<byte> psk = Convert.FromHexString(preSharedKey);

        X25519.DeriveSenderSharedKey(ss, ssk, rpk, psk);
        X25519.DeriveRecipientSharedKey(rs, rsk, spk, psk);

        Assert.AreEqual(sharedKey, Convert.ToHexString(ss).ToLower());
        Assert.AreEqual(sharedKey, Convert.ToHexString(rs).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(SharedKeyInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void DeriveSharedKey_Invalid(int sharedKeySize, int privateKeySize, int publicKeySize, int preSharedKeySize)
    {
        var s = new byte[sharedKeySize];
        var sk = new byte[privateKeySize];
        var pk = new byte[publicKeySize];
        var psk = new byte[preSharedKeySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveSenderSharedKey(s, sk, pk, psk));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => X25519.DeriveRecipientSharedKey(s, sk, pk, psk));
    }
}
