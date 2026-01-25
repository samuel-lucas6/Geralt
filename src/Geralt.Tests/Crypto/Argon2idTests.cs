namespace Geralt.Tests;

[TestClass]
public class Argon2idTests
{
    // https://cyberchef.org/#recipe=Argon2(%7B'option':'UTF8','string':'somesaltsomesalt'%7D,1,8,1,32,'Argon2id','Hex%20hash')
    // https://cyberchef.org/#recipe=Argon2(%7B'option':'UTF8','string':'saltsaltsaltsalt'%7D,1,8,1,32,'Argon2id','Hex%20hash')
    public static IEnumerable<object[]> KeyDerivationTestVectors()
    {
        yield return
        [
            "39af95f616f16373dccc34c41b3d252f29024b24d3d6010c7a88be5ba3217e48",
            "",
            "736f6d6573616c74736f6d6573616c74",
            Argon2id.MinIterations,
            Argon2id.MinMemorySize
        ];
        yield return
        [
            "05b6ca8f8038b683887ad4916533858b49cb52040126c134f4c6e9d8711b8c09",
            "password",
            "736f6d6573616c74736f6d6573616c74",
            Argon2id.MinIterations,
            Argon2id.MinMemorySize
        ];
        yield return
        [
            "6aa57ab96e4a537fc5155db6a9a5ad9b114575dbd607b96f11680d2dc6026723",
            "",
            "73616c7473616c7473616c7473616c74",
            Argon2id.MinIterations,
            Argon2id.MinMemorySize
        ];
        yield return
        [
            "a161476453875fe1b4add3d5accd478395c9d13ae6e4218bab14d419ce605ec2",
            "",
            "736f6d6573616c74736f6d6573616c74",
            Argon2id.MinIterations * 2,
            Argon2id.MinMemorySize
        ];
        yield return
        [
            "debdca25b1198382332d28358c6bf605e6e4a3322fe45ab290cc406f78897aa4",
            "",
            "736f6d6573616c74736f6d6573616c74",
            Argon2id.MinIterations,
            Argon2id.MinMemorySize * 2
        ];
    }

    // https://github.com/RustCrypto/password-hashes/blob/master/argon2/tests/phc_strings.rs
    // https://github.com/jedisct1/libsodium/blob/master/test/default/pwhash_argon2id.c
    public static IEnumerable<object[]> ValidStringTestVectors()
    {
        yield return
        [
            "$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow",
            "password"
        ];
        yield return
        [
            "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
            "password"
        ];
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        yield return
        [
            "$argon2id$v=19$m=4096,t=19,p=1$PkEgMTYtYnl0ZXMgc2FsdA$ltB/ue1kPtBMBGfsysMpPigE6hiNEKZ9vs8vLNVDQGA",
            "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg "
        ];
        yield return
        [
            "$argon2id$v=19$m=4096,t=1,p=3$PkEgcHJldHR5IGxvbmcgc2FsdA$HUqx5Z1b/ZypnUrvvJ5UC2Q+T6Q1WwASK/Kr9dRbGA0",
            "K3S=KyH#)36_?]LxeR8QNKw6X=gFbxai$C%29V*"
        ];
    }

    public static IEnumerable<object[]> TamperedStringTestVectors()
    {
        // Wrong memorySize
        yield return
        [
            "$argon2id$v=19$m=8,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Wrong iterations
        yield return
        [
            "$argon2id$v=19$m=4882,t=1,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Wrong parallelism
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=2$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            " "
        ];
        // Truncated salt
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmE$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Truncated hash
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNc",
            ""
        ];
        // Wrong password
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            " "
        ];
    }

    // https://github.com/RustCrypto/password-hashes/blob/master/argon2/tests/phc_strings.rs
    public static IEnumerable<object[]> InvalidPhcStringFormatTestVectors()
    {
        // Missing version
        yield return
        [
            "$argon2id$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Invalid version
        yield return
        [
            "$argon2id$v=42$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // v isn't a number
        yield return
        [
            "$argon2id$v=dummy$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Missing m
        yield return
        [
            "$argon2id$v=19$t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // m isn't a number
        yield return
        [
            "$argon2id$v=19$m=dummy,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // m is too small
        yield return
        [
            "$argon2id$v=19$m=0,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // m is too big
        yield return
        [
            "$argon2id$v=19$m=4294967296,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Missing t
        yield return
        [
            "$argon2id$v=19$m=4882,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // t isn't a number
        yield return
        [
            "$argon2id$v=19$m=4882,t=dummy,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // t is too small
        yield return
        [
            "$argon2id$v=19$m=4882,t=0,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // t is too big
        yield return
        [
            "$argon2id$v=19$m=4882,t=4294967296,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Missing p
        yield return
        [
            "$argon2id$v=19$m=4882,t=2$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // p isn't a number
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=dummy$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // p is too small
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=0$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // p is too big
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=16777216$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Missing salt
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Missing hash
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw",
            ""
        ];
        // Missing commas
        yield return
        [
            "$argon2id$v=19$m=4882t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        yield return
        [
            "$argon2id$v=19$m=4882,t=2p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Missing dollars
        yield return
        [
            "$argon2id$v=19m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOwNm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Non-Base64 characters
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEO!$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        yield return
        [
            "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcp!",
            ""
        ];
    }

    public static IEnumerable<object[]> InvalidStringTestVectors()
    {
        // Missing algorithm
        yield return
        [
            "$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
            ""
        ];
        // Wrong algorithm
        yield return
        [
            "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$Pw5Jovc42Um8SICQCKEKAy+uH3ismu7FMNtTeDmVWzo",
            ""
        ];
        yield return
        [
            "$argon2d$v=19$m=4096,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$bPKG5lGYd2cZrmVuzsN1nCY6dluKXeCOY57YaZHNMBo",
            ""
        ];
        // Small hash
        yield return
        [
            "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbH$AKal+Q",
            ""
        ];
        // Long hash
        yield return
        [
            "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$EyCMRolQLn0SWMIxqaEjbg1Pza/F22HoRXyn5JI9n0XPbrQPlL86IU45f8VfN4+dCEIT2h6Ekf8wVPM",
            ""
        ];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, Argon2id.KeySize);
        Assert.AreEqual(16, Argon2id.SaltSize);
        Assert.AreEqual(128, Argon2id.HashSize);
        Assert.AreEqual(16, Argon2id.MinKeySize);
        Assert.AreEqual(1, Argon2id.MinIterations);
        Assert.AreEqual(8192, Argon2id.MinMemorySize);
    }

    [TestMethod]
    [DynamicData(nameof(KeyDerivationTestVectors))]
    public void DeriveKey_Valid(string outputKeyingMaterial, string password, string salt, int iterations, int memorySize)
    {
        Span<byte> okm = stackalloc byte[outputKeyingMaterial.Length / 2];
        Span<byte> p = Encoding.UTF8.GetBytes(password);
        Span<byte> s = Convert.FromHexString(salt);

        Argon2id.DeriveKey(okm, p, s, iterations, memorySize);

        Assert.AreEqual(outputKeyingMaterial, Convert.ToHexString(okm).ToLower());
    }

    [TestMethod]
    [DataRow(Argon2id.MinKeySize - 1, Argon2id.KeySize, Argon2id.SaltSize, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinKeySize, Argon2id.KeySize, Argon2id.SaltSize + 1, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinKeySize, Argon2id.KeySize, Argon2id.SaltSize - 1, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinKeySize, Argon2id.KeySize, Argon2id.SaltSize, Argon2id.MinIterations - 1, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.MinKeySize, Argon2id.KeySize, Argon2id.SaltSize, Argon2id.MinIterations, Argon2id.MinMemorySize - 1)]
    public void DeriveKey_Invalid(int outputKeyingMaterialSize, int passwordSize, int saltSize, int iterations, int memorySize)
    {
        var okm = new byte[outputKeyingMaterialSize];
        var p = new byte[passwordSize];
        var s = new byte[saltSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Argon2id.DeriveKey(okm, p, s, iterations, memorySize));
    }

    [TestMethod]
    [DataRow("", Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow("correct horse battery staple", Argon2id.MinIterations * 2, Argon2id.MinMemorySize)]
    [DataRow("correct horse battery staple", Argon2id.MinIterations, Argon2id.MinMemorySize * 2)]
    public void ComputeHash_Valid(string password, int iterations, int memorySize)
    {
        Span<char> h = stackalloc char[Argon2id.HashSize];
        Span<byte> p = Encoding.UTF8.GetBytes(password);

        Argon2id.ComputeHash(h, p, iterations, memorySize);

        bool valid = Argon2id.VerifyHash(h, p);
        Assert.IsTrue(valid);

        bool rehash = Argon2id.NeedsRehash(h, iterations, memorySize);
        Assert.IsFalse(rehash);
    }

    [TestMethod]
    [DataRow(Argon2id.HashSize + 1, Argon2id.KeySize, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.HashSize - 1, Argon2id.KeySize, Argon2id.MinIterations, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.HashSize, Argon2id.KeySize, Argon2id.MinIterations - 1, Argon2id.MinMemorySize)]
    [DataRow(Argon2id.HashSize, Argon2id.KeySize, Argon2id.MinIterations, Argon2id.MinMemorySize - 1)]
    public void ComputeHash_Invalid(int hashSize, int passwordSize, int iterations, int memorySize)
    {
        var h = new char[hashSize];
        var p = new byte[passwordSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Argon2id.ComputeHash(h, p, iterations, memorySize));
    }

    [TestMethod]
    [DynamicData(nameof(ValidStringTestVectors))]
    public void VerifyHash_Valid(string hash, string password)
    {
        Span<byte> p = Encoding.UTF8.GetBytes(password);

        bool valid = Argon2id.VerifyHash(hash, p);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(TamperedStringTestVectors))]
    [DynamicData(nameof(InvalidPhcStringFormatTestVectors))]
    public void VerifyHash_Tampered(string hash, string password)
    {
        Span<byte> p = Encoding.UTF8.GetBytes(password);

        bool valid = Argon2id.VerifyHash(hash, p);

        Assert.IsFalse(valid);
    }

    [TestMethod]
    [DynamicData(nameof(InvalidStringTestVectors))]
    public void VerifyHash_Invalid(string hash, string password)
    {
        var p = Encoding.UTF8.GetBytes(password);

        if (!hash.StartsWith("$argon2id$")) {
            Assert.ThrowsExactly<FormatException>(() => Argon2id.VerifyHash(hash, p));
        }
        else {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Argon2id.VerifyHash(hash, p));
        }
    }

    [TestMethod]
    [DataRow("$argon2id$v=19$m=16384,t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us", 3, 16777216)]
    [DataRow("$argon2id$v=19$m=16384,t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us", 4, 16777216)]
    [DataRow("$argon2id$v=19$m=16384,t=3,p=1$9jzdCOZe8dvfNWga1TS9wQ$ZdlB31msrCUY3R83w6GRGXdmq2zgUcLQGwnedCzU4Us", 3, 33554432)]
    public void NeedsRehash_Valid(string hash, int iterations, int memorySize)
    {
        bool expected = !hash.Contains($"m={memorySize / 1024},t={iterations}");

        bool rehash = Argon2id.NeedsRehash(hash, iterations, memorySize);

        Assert.AreEqual(expected, rehash);
    }

    [TestMethod]
    [DynamicData(nameof(InvalidPhcStringFormatTestVectors))]
    public void NeedsRehash_Tampered(string hash, string password, int iterations = Argon2id.MinIterations, int memorySize = Argon2id.MinMemorySize)
    {
        Assert.ThrowsExactly<FormatException>(() => Argon2id.NeedsRehash(hash, iterations, memorySize));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidStringTestVectors))]
    public void NeedsRehash_Invalid(string hash, string password, int iterations = Argon2id.MinIterations, int memorySize = Argon2id.MinMemorySize)
    {
        if (!hash.StartsWith("$argon2id$")) {
            Assert.ThrowsExactly<FormatException>(() => Argon2id.NeedsRehash(hash, iterations, memorySize));
        }
        else {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Argon2id.NeedsRehash(hash, iterations, memorySize));
        }
    }
}
