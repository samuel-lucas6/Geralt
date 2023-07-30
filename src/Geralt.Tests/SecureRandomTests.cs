using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class SecureRandomTests
{
    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, SecureRandom.SeedSize);
        Assert.AreEqual("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", SecureRandom.AlphabeticChars);
        Assert.AreEqual("0123456789", SecureRandom.NumericChars);
        Assert.AreEqual("!#$%&'()*+,-./:;<=>?@[]^_`{}~", SecureRandom.SymbolChars);
        Assert.AreEqual(SecureRandom.AlphabeticChars + SecureRandom.NumericChars, SecureRandom.AlphanumericChars);
        Assert.AreEqual(SecureRandom.AlphanumericChars + SecureRandom.SymbolChars, SecureRandom.AlphanumericSymbolChars);
        Assert.AreEqual(2, SecureRandom.MinUpperBound);
        Assert.AreEqual(8, SecureRandom.MinStringLength);
        Assert.AreEqual(128, SecureRandom.MaxStringLength);
        Assert.AreEqual(4, SecureRandom.MinWordCount);
        Assert.AreEqual(20, SecureRandom.MaxWordCount);
    }

    [TestMethod]
    public void Fill_Valid()
    {
        Span<byte> buffer = stackalloc byte[ChaCha20Poly1305.KeySize];

        SecureRandom.Fill(buffer);

        Assert.IsFalse(buffer.SequenceEqual(new byte[buffer.Length]));
    }

    [TestMethod]
    public void Fill_Invalid()
    {
        var buffer = Array.Empty<byte>();

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.Fill(buffer));
    }

    [TestMethod]
    public void FillDeterministic_Valid()
    {
        Span<byte> buffer = stackalloc byte[ChaCha20Poly1305.KeySize];
        Span<byte> seed = stackalloc byte[SecureRandom.SeedSize];

        SecureRandom.FillDeterministic(buffer, seed);

        Assert.IsFalse(buffer.SequenceEqual(new byte[buffer.Length]));
    }

    [TestMethod]
    [DataRow(0, SecureRandom.SeedSize)]
    [DataRow(ChaCha20Poly1305.KeySize, SecureRandom.SeedSize + 1)]
    [DataRow(ChaCha20Poly1305.KeySize, SecureRandom.SeedSize - 1)]
    public void FillDeterministic_Invalid(int bufferSize, int seedSize)
    {
        var buffer = new byte[bufferSize];
        var seed = new byte[seedSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.FillDeterministic(buffer, seed));
    }

    [TestMethod]
    public void GetInt32_Valid()
    {
        int number = SecureRandom.GetInt32(SecureRandom.MinUpperBound);

        Assert.IsTrue(number is < SecureRandom.MinUpperBound and >= 0);
    }

    [TestMethod]
    public void GetInt32_Invalid()
    {
        int upperBound = SecureRandom.MinUpperBound - 1;

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.GetInt32(upperBound));
    }

    [TestMethod]
    [DataRow(SecureRandom.MinWordCount, ' ', false, false)]
    [DataRow(SecureRandom.MaxWordCount, ' ', false, false)]
    [DataRow(SecureRandom.MinWordCount, '_', false, false)]
    [DataRow(SecureRandom.MinWordCount, ' ', true, false)]
    [DataRow(SecureRandom.MinWordCount, ' ', false, true)]
    [DataRow(SecureRandom.MinWordCount, ' ', true, true)]
    public void GetPassphrase_Valid(int wordCount, char separatorChar, bool capitalize, bool includeNumber)
    {
        char[] passphrase = SecureRandom.GetPassphrase(wordCount, separatorChar, capitalize, includeNumber);

        Assert.AreEqual(wordCount - 1, passphrase.Count(c => c == separatorChar));
        Assert.AreNotEqual(separatorChar, passphrase[^1]);
        Assert.AreEqual(capitalize ? wordCount : 0, passphrase.Count(char.IsUpper));
        Assert.AreEqual(capitalize, char.IsUpper(passphrase[0]));
        Assert.AreEqual(includeNumber, passphrase.Any(char.IsDigit));
    }

    [TestMethod]
    [DataRow(SecureRandom.MaxWordCount + 1)]
    [DataRow(SecureRandom.MinWordCount - 1)]
    public void GetPassphrase_Invalid(int wordCount)
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.GetPassphrase(wordCount));
    }

    [TestMethod]
    public void GetString_Valid()
    {
        int length = SecureRandom.MaxStringLength;
        string random = SecureRandom.GetString(length, SecureRandom.AlphabeticChars);

        Assert.AreEqual(length, random.Length);
        Assert.IsTrue(random.All(char.IsLetter));
    }

    [TestMethod]
    [DataRow(SecureRandom.MaxStringLength + 1)]
    [DataRow(SecureRandom.MinStringLength - 1)]
    public void GetString_Invalid(int length)
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.GetString(length));
    }
}
