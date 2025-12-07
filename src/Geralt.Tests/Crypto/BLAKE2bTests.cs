namespace Geralt.Tests;

[TestClass]
public class BLAKE2bTests
{
    // https://cyberchef.org/#recipe=BLAKE2b('128','Hex',%7B'option':'Hex','string':''%7D)
    // https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json
    public static IEnumerable<object[]> UnkeyedTestVectors()
    {
        yield return
        [
            "cae66941d9efbd404e4d88758ea67670",
            ""
        ];
        yield return
        [
            "3345524abf6bbe1809449224b5972c41790b6cf2",
            ""
        ];
        yield return
        [
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
            ""
        ];
        yield return
        [
            "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100",
            ""
        ];
        yield return
        [
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            ""
        ];
        yield return
        [
            "cbaa0ba7d482b1f301109ae41051991a3289bc1198005af226c5e4f103b66579f461361044c8ba3439ff12c515fb29c52161b7eb9c2837b76a5dc33f7cb2e2e8",
            "0001020304"
        ];
        yield return
        [
            "2fc6e69fa26a89a5ed269092cb9b2a449a4409a7a44011eecad13d7c4b0456602d402fa5844f1a7a758136ce3d5d8d0e8b86921ffff4f692dd95bdc8e5ff0052",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ];
        yield return
        [
            "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        ];
        yield return
        [
            "cfaeab268cd075a5a6aed515023a032d54f2f2ff733ce0cbc78db51db4504d675923f82746d6594606ad5d67734b11a67cc6a468c2032e43ca1a94c6273a985e",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091929394959697"
        ];
    }

    // https://cyberchef.org/#recipe=BLAKE2b('128','Hex',%7B'option':'Hex','string':'000102030405060708090a0b0c0d0e0f'%7D)
    // https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
    public static IEnumerable<object[]> KeyedTestVectors()
    {
        yield return
        [
            "083aac7ba77bc664005d821eb8bfa4d9",
            "",
            "000102030405060708090a0b0c0d0e0f"
        ];
        yield return
        [
            "7086befde32d9552341beeacc70e6ffdf5c02ab7",
            "",
            "000102030405060708090a0b0c0d0e0f10111213"
        ];
        yield return
        [
            "4e51e7a913fc80137da52880fecca175bf81e117d5c68126dc2774033517ea0d",
            "",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ];
        yield return
        [
            "b256ae5bd7d7b52b56f7a7b5f15feba492ed48b9d5b19657bcf5caa744661b6b7b303da35c2121dfd72cf05454d37563",
            "",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
        ];
        yield return
        [
            "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
            "",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ];
        yield return
        [
            "098084b51fd13deae5f4320de94a688ee07baea2800486689a8636117b46c1f4c1f6af7f74ae7c857600456a58a3af251dc4723a64cc7c0a5ab6d9cac91c20bb",
            "0001020304",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ];
        yield return
        [
            "65676d800617972fbd87e4b9514e1c67402b7a331096d3bfac22f1abb95374abc942f16e9ab0ead33b87c91968a6e509e119ff07787b3ef483e1dcdccf6e3022",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ];
        yield return
        [
            "72065ee4dd91c2d8509fa1fc28a37c7fc9fa7d5b3f8ad3d0d7a25626b57b1b44788d4caf806290425f9890a3a2a35a905ab4b37acfd0da6e4517b2525c9651e4",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ];
        yield return
        [
            "24ce0addaa4c65038bd1b1c0f1452a0b128777aabc94a29df2fd6c7e2f85f8ab9ac7eff516b0e0a825c84a24cfe492eaad0a6308e46dd42fe8333ab971bb30ca",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091929394959697",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ];
    }

    // https://github.com/emilbayes/blake2b/blob/master/test-vectors.json
    public static IEnumerable<object[]> KeyDerivationTestVectors()
    {
        yield return
        [
            "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            ""
        ];
        yield return
        [
            "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "00000000000000000000000000000000",
            "",
            ""
        ];
        yield return
        [
            "5fbe885c4b2d4e0d78dc5905622a277a",
            "000102030405060708090a0b0c0d0e0f",
            "35313236666232613337343030643261",
            "35623662343165643962333433666530",
            "000102030405060708090a0b0c0d0e"
        ];
        yield return
        [
            "9b273ebe335540b87be899abe169389ed61ed262c3a0a16e4998bbf752f0bee3",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "35313236666232613337343030643261",
            "35623662343165643962333433666530",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
        ];
        yield return
        [
            "5fcdcc02be7714a0dbc77df498bf999ea9225d564adca1c121c9af03af92cac8177b9b4a86bcc47c79aa32aac58a3fef967b2132e9352d4613fe890beed2571b",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "35313236666232613337343030643261",
            "35623662343165643962333433666530",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e"
        ];
    }

    public static IEnumerable<object[]> TagInvalidParameterSizes()
    {
        yield return [BLAKE2b.MaxTagSize + 1, 1, BLAKE2b.KeySize];
        yield return [BLAKE2b.MinTagSize - 1, 1, BLAKE2b.KeySize];
        yield return [BLAKE2b.TagSize, 1, BLAKE2b.MaxKeySize + 1];
        yield return [BLAKE2b.TagSize, 1, BLAKE2b.MinKeySize - 1];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, BLAKE2b.HashSize);
        Assert.AreEqual(32, BLAKE2b.KeySize);
        Assert.AreEqual(32, BLAKE2b.TagSize);
        Assert.AreEqual(128, BLAKE2b.BlockSize);
        Assert.AreEqual(16, BLAKE2b.SaltSize);
        Assert.AreEqual(16, BLAKE2b.PersonalizationSize);
        Assert.AreEqual(16, BLAKE2b.MinHashSize);
        Assert.AreEqual(64, BLAKE2b.MaxHashSize);
        Assert.AreEqual(16, BLAKE2b.MinTagSize);
        Assert.AreEqual(64, BLAKE2b.MaxTagSize);
        Assert.AreEqual(16, BLAKE2b.MinKeySize);
        Assert.AreEqual(64, BLAKE2b.MaxKeySize);
    }

    [TestMethod]
    [DynamicData(nameof(UnkeyedTestVectors), DynamicDataSourceType.Method)]
    public void ComputeHash_Valid(string hash, string message)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> m = Convert.FromHexString(message);

        BLAKE2b.ComputeHash(h, m);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());
    }

    [TestMethod]
    [DataRow(BLAKE2b.MaxHashSize + 1, 1)]
    [DataRow(BLAKE2b.MinHashSize - 1, 1)]
    public void ComputeHash_Invalid(int hashSize, int messageSize)
    {
        var h = new byte[hashSize];
        var m = new byte[messageSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeHash(h, m));
    }

    [TestMethod]
    [DynamicData(nameof(KeyedTestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string key)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        BLAKE2b.ComputeTag(t, m, k);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TagInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => BLAKE2b.ComputeTag(t, m, k));
    }

    [TestMethod]
    [DynamicData(nameof(KeyedTestVectors), DynamicDataSourceType.Method)]
    public void VerifyTag_Valid(string tag, string message, string key)
    {
        Span<byte> t = Convert.FromHexString(tag);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        bool valid = BLAKE2b.VerifyTag(t, m, k);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(KeyedTestVectors), DynamicDataSourceType.Method)]
    public void VerifyTag_Tampered(string tag, string message, string key)
    {
        var parameters = new Dictionary<string, byte[]>
        {
            { "t", Convert.FromHexString(tag) },
            { "m", Convert.FromHexString(message) },
            { "k", Convert.FromHexString(key) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            bool valid = BLAKE2b.VerifyTag(parameters["t"], parameters["m"], parameters["k"]);
            param[0]--;
            Assert.IsFalse(valid);
        }
    }

    [TestMethod]
    [DynamicData(nameof(TagInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void VerifyTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => BLAKE2b.VerifyTag(t, m, k));
    }

    [TestMethod]
    [DynamicData(nameof(KeyDerivationTestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string outputKeyingMaterial, string inputKeyingMaterial, string personalization, string salt, string info)
    {
        Span<byte> okm = stackalloc byte[outputKeyingMaterial.Length / 2];
        Span<byte> ikm = Convert.FromHexString(inputKeyingMaterial);
        Span<byte> p = Convert.FromHexString(personalization);
        Span<byte> s = Convert.FromHexString(salt);
        Span<byte> i = Convert.FromHexString(info);

        BLAKE2b.DeriveKey(okm, ikm, p, s, i);

        Assert.AreEqual(outputKeyingMaterial, Convert.ToHexString(okm).ToLower());
    }

    [TestMethod]
    [DataRow(BLAKE2b.MaxKeySize + 1, BLAKE2b.KeySize, BLAKE2b.PersonalizationSize, BLAKE2b.SaltSize, 1)]
    [DataRow(BLAKE2b.MinKeySize - 1, BLAKE2b.KeySize, BLAKE2b.PersonalizationSize, BLAKE2b.SaltSize, 1)]
    [DataRow(BLAKE2b.KeySize, BLAKE2b.MaxKeySize + 1, BLAKE2b.PersonalizationSize, BLAKE2b.SaltSize, 1)]
    [DataRow(BLAKE2b.KeySize, BLAKE2b.MinKeySize - 1, BLAKE2b.PersonalizationSize, BLAKE2b.SaltSize, 1)]
    [DataRow(BLAKE2b.KeySize, BLAKE2b.KeySize, BLAKE2b.PersonalizationSize + 1, BLAKE2b.SaltSize, 1)]
    [DataRow(BLAKE2b.KeySize, BLAKE2b.KeySize, BLAKE2b.PersonalizationSize - 1, BLAKE2b.SaltSize, 1)]
    [DataRow(BLAKE2b.KeySize, BLAKE2b.KeySize, BLAKE2b.PersonalizationSize, BLAKE2b.SaltSize + 1, 1)]
    [DataRow(BLAKE2b.KeySize, BLAKE2b.KeySize, BLAKE2b.PersonalizationSize, BLAKE2b.SaltSize - 1, 1)]
    public void DeriveKey_Invalid(int outputKeyingMaterialSize, int inputKeyingMaterialSize, int personalizationSize, int saltSize, int infoSize)
    {
        var okm = new byte[outputKeyingMaterialSize];
        var ikm = new byte[inputKeyingMaterialSize];
        var p = new byte[personalizationSize];
        var s = new byte[saltSize];
        var i = new byte[infoSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => BLAKE2b.DeriveKey(okm, ikm, p, s, i));
    }
}
