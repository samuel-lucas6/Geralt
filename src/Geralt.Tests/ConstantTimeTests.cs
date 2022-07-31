using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class ConstantTimeTests
{
    [TestMethod]
    public void Equals_IdenticalInputs()
    {
        const string quote = "Lambert, Lambert, what a prick.";
        Span<byte> a = Encoding.UTF8.GetBytes(quote);
        Span<byte> b = Encoding.UTF8.GetBytes(quote);
        bool equal = ConstantTime.Equals(a, b);
        Assert.IsTrue(equal);
    }
    
    [TestMethod]
    public void Equals_DifferentInputLengths()
    {
        Span<byte> a = Encoding.UTF8.GetBytes("Damn, you're ugly.");
        Span<byte> b = Encoding.UTF8.GetBytes("Damn, you're ugly...");
        bool equal = ConstantTime.Equals(a, b);
        Assert.IsFalse(equal);
    }
    
    [TestMethod]
    public void Equals_DifferentInputs()
    {
        Span<byte> a = Encoding.UTF8.GetBytes("Evil is evil.");
        Span<byte> b = Encoding.UTF8.GetBytes("Good is good.");
        bool equal = ConstantTime.Equals(a, b);
        Assert.IsFalse(equal);
    }
    
    [TestMethod]
    public void Increment_ValidBuffer()
    {
        Span<byte> original = stackalloc byte[ChaCha20Poly1305.NonceSize];
        Span<byte> counter = stackalloc byte[ChaCha20Poly1305.NonceSize];
        ConstantTime.Increment(counter);
        Assert.IsFalse(counter.SequenceEqual(original));
    }
    
    [TestMethod]
    public void Increment_InvalidBuffer()
    {
        var counter = Array.Empty<byte>();
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.Increment(counter));
    }
    
    [TestMethod]
    public void IsAllZeros_AllZeroBuffer()
    {
        Span<byte> buffer = stackalloc byte[ChaCha20Poly1305.NonceSize];
        bool allZeros = ConstantTime.IsAllZeros(buffer);
        Assert.IsTrue(allZeros);
    }
    
    [TestMethod]
    public void IsAllZeros_NonZeroBuffer()
    {
        Span<byte> buffer = Encoding.UTF8.GetBytes("I believe in the sword.");
        bool allZeros = ConstantTime.IsAllZeros(buffer);
        Assert.IsFalse(allZeros);
    }
    
    [TestMethod]
    public void IsAllZeros_EmptyBuffer()
    {
        byte[]? buffer = null;
        bool allZeros = ConstantTime.IsAllZeros(buffer);
        Assert.IsTrue(allZeros);
    }
    
    [TestMethod]
    public void Add_ValidInputs()
    {
        byte[] a = {0x01};
        byte[] b = {0x02};
        byte[] expected = {0x03};
        Span<byte> buffer = stackalloc byte[a.Length];
        ConstantTime.Add(buffer, a, b);
        Assert.IsTrue(buffer.SequenceEqual(expected));
    }
    
    [TestMethod]
    public void Add_InvalidInputs()
    {
        byte[] a = {0x01};
        byte[] b = {0x02, 0x05};
        var buffer = new byte[a.Length];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.Add(buffer, a, b));
    }
    
    [TestMethod]
    public void Add_InvalidBuffer()
    {
        var buffer = Array.Empty<byte>();
        byte[] a = {0x01};
        byte[] b = {0x02};
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.Add(buffer, a, b));
    }
    
    [TestMethod]
    public void Subtract_ValidInputs()
    {
        byte[] a = {0x02};
        byte[] b = {0x01};
        byte[] expected = {0x01};
        Span<byte> buffer = stackalloc byte[a.Length];
        ConstantTime.Subtract(buffer, a, b);
        Assert.IsTrue(buffer.SequenceEqual(expected));
    }
    
    [TestMethod]
    public void Subtract_InvalidInputs()
    {
        byte[] a = {0x01};
        byte[] b = {0x02, 0x05};
        var buffer = new byte[a.Length];
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.Subtract(buffer, a, b));
    }
    
    [TestMethod]
    public void Subtract_InvalidBuffer()
    {
        var buffer = Array.Empty<byte>();
        byte[] a = {0x02};
        byte[] b = {0x01};
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.Subtract(buffer, a, b));
    }
    
    [TestMethod]
    public void IsLessThan_False()
    {
        byte[] a = {0x02};
        byte[] b = {0x01};
        bool aLessThan = ConstantTime.IsLessThan(a, b);
        Assert.IsFalse(aLessThan);
    }
    
    [TestMethod]
    public void IsLessThan_True()
    {
        byte[] a = {0x01};
        byte[] b = {0x02};
        bool aLessThan = ConstantTime.IsLessThan(a, b);
        Assert.IsTrue(aLessThan);
    }
    
    [TestMethod]
    public void IsLessThan_InvalidInputs()
    {
        byte[] a = {0x01};
        byte[] b = {0x02, 0x05};
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.IsLessThan(a, b));
    }

    [TestMethod]
    public void IsGreaterThan_False()
    {
        byte[] a = {0x01};
        byte[] b = {0x02};
        bool aGreaterThan = ConstantTime.IsGreaterThan(a, b);
        Assert.IsFalse(aGreaterThan);
    }
    
    [TestMethod]
    public void IsGreaterThan_True()
    {
        byte[] a = {0x02};
        byte[] b = {0x01};
        bool aGreaterThan = ConstantTime.IsGreaterThan(a, b);
        Assert.IsTrue(aGreaterThan);
    }
    
    [TestMethod]
    public void IsGreaterThan_InvalidInputs()
    {
        byte[] a = {0x01};
        byte[] b = {0x02, 0x05};
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.IsGreaterThan(a, b));
    }
}