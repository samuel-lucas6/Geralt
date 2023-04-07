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
    public void GetPassphrase_Valid()
    {
        const char separatorChar = ' ';
        char[] passphrase = SecureRandom.GetPassphrase(SecureRandom.MinWordCount, separatorChar, capitalise: false, includeNumber: true);
        
        Assert.IsTrue(passphrase.Contains(separatorChar));
        Assert.IsFalse(passphrase[^1] == separatorChar);
        Assert.IsTrue(char.IsLower(passphrase[0]));
        Assert.IsTrue(passphrase.Any(char.IsDigit));
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
        
        Assert.IsTrue(random.Length == length);
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