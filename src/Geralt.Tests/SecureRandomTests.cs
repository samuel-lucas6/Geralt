using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class SecureRandomTests
{
    [TestMethod]
    public void Fill_NotAllZeros()
    {
        Span<byte> buffer = stackalloc byte[ChaCha20Poly1305.KeySize];
        SecureRandom.Fill(buffer);
        Assert.IsFalse(buffer.SequenceEqual(new byte[buffer.Length]));
    }
    
    [TestMethod]
    public void Fill_InvalidBuffer()
    {
        var buffer = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.Fill(buffer));
    }
    
    [TestMethod]
    public void FillDeterministic_NotAllZeros()
    {
        Span<byte> buffer = stackalloc byte[ChaCha20Poly1305.KeySize];
        Span<byte> seed = stackalloc byte[SecureRandom.SeedSize];
        SecureRandom.FillDeterministic(buffer, seed);
        Assert.IsFalse(buffer.SequenceEqual(new byte[buffer.Length]));
    }
    
    [TestMethod]
    public void FillDeterministic_InvalidBuffer()
    {
        var buffer = Array.Empty<byte>();
        var seed = new byte[SecureRandom.SeedSize];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.FillDeterministic(buffer, seed));
    }
    
    [TestMethod]
    public void FillDeterministic_InvalidSeed()
    {
        var buffer = new byte[ChaCha20Poly1305.KeySize];
        var seed = new byte[SecureRandom.SeedSize - 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.FillDeterministic(buffer, seed));
        seed = new byte[SecureRandom.SeedSize + 1];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.FillDeterministic(buffer, seed));
    }
    
    [TestMethod]
    public void GetInt32_ValidUpperBound()
    {
        int number = SecureRandom.GetInt32(SecureRandom.MinUpperBound);
        Assert.IsTrue(number < SecureRandom.MinUpperBound);
        Assert.IsTrue(number >= 0);
    }
    
    [TestMethod]
    public void GetInt32_InvalidUpperBound()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.GetInt32(SecureRandom.MinUpperBound - 1));
    }
    
    [TestMethod]
    public void GetPassphrase_ValidDefaultChars()
    {
        const char separatorChar = '-';
        char[] passphrase = SecureRandom.GetPassphrase(SecureRandom.MinWordCount);
        Assert.IsTrue(passphrase.Contains(separatorChar));
        Assert.IsTrue(char.IsLower(passphrase[0]));
        Assert.IsFalse(passphrase[^1] == separatorChar);
        Assert.IsFalse(passphrase.Any(char.IsDigit));
    }
    
    [TestMethod]
    public void GetPassphrase_ValidCustomChars()
    {
        const char separatorChar = '=';
        char[] passphrase = SecureRandom.GetPassphrase(SecureRandom.MinWordCount, separatorChar, capitalise: false, includeNumber: true);
        Assert.IsFalse(passphrase.Contains('-'));
        Assert.IsTrue(passphrase.Contains(separatorChar));
        Assert.IsTrue(char.IsLower(passphrase[0]));
        Assert.IsFalse(passphrase[^1] == separatorChar);
        Assert.IsTrue(passphrase.Any(char.IsDigit));
    }
    
    [TestMethod]
    public void GetPassphrase_InvalidWordCount()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.GetPassphrase(SecureRandom.MinWordCount - 1));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.GetPassphrase(SecureRandom.MaxWordCount + 1));
    }
    
    [TestMethod]
    public void GetString_ValidAlphabeticChars()
    {
        string randomFileName = SecureRandom.GetString(SecureRandom.MaxStringLength, SecureRandom.AlphabeticChars);
        Assert.IsTrue(randomFileName.All(char.IsLetter));
    }
    
    [TestMethod]
    public void GetString_ValidNumericChars()
    {
        string randomFileName = SecureRandom.GetString(SecureRandom.MaxStringLength, SecureRandom.NumericChars);
        Assert.IsTrue(randomFileName.All(char.IsDigit));
    }
    
    [TestMethod]
    public void GetString_ValidAlphanumericChars()
    {
        string randomFileName = SecureRandom.GetString(SecureRandom.MaxStringLength, SecureRandom.AlphanumericChars);
        Assert.IsFalse(randomFileName.Any(char.IsSymbol));
        Assert.IsFalse(randomFileName.Any(char.IsPunctuation));
        Assert.IsTrue(randomFileName.Any(char.IsDigit));
        Assert.IsTrue(randomFileName.Any(char.IsLetter));
    }
    
    [TestMethod]
    public void GetString_ValidAlphanumericSymbolChars()
    {
        string randomFileName = SecureRandom.GetString(SecureRandom.MaxStringLength, SecureRandom.AlphanumericSymbolChars);
        Assert.IsTrue(randomFileName.Any(char.IsSymbol) || randomFileName.Any(char.IsPunctuation));
        Assert.IsTrue(randomFileName.Any(char.IsDigit));
        Assert.IsTrue(randomFileName.Any(char.IsLetter));
    }
    
    [TestMethod]
    public void GetString_InvalidLength()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.GetString(SecureRandom.MinStringLength - 1));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureRandom.GetString(SecureRandom.MaxStringLength + 1));
    }
}