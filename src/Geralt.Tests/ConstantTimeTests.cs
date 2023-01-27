using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class ConstantTimeTests
{
    public static IEnumerable<object[]> AddSubtractInvalidParameterSizes()
    {
        yield return new object[] { 0, 1, 1 };
        yield return new object[] { 1, 0, 1 };
        yield return new object[] { 1, 1, 0 };
        yield return new object[] { 1, 1, 2 };
        yield return new object[] { 1, 2, 1 };
        yield return new object[] { 2, 1, 1 };
    }
    
    public static IEnumerable<object[]> GreaterLessInvalidParameterSizes()
    {
        yield return new object[] { 0, 1 };
        yield return new object[] { 1, 0 };
        yield return new object[] { 4, 2 };
    }
    
    [TestMethod]
    [DataRow(true, "Lambert, Lambert, what a prick.", "Lambert, Lambert, what a prick.")]
    [DataRow(false, "Evil is evil.", "Good is good.")]
    [DataRow(false, "Damn, you're ugly.", "Damn, you're ugly...")]
    public void Equals_Valid(bool expected, string aString, string bString)
    {
        Span<byte> a = Encoding.UTF8.GetBytes(aString);
        Span<byte> b = Encoding.UTF8.GetBytes(bString);
        
        bool equal = ConstantTime.Equals(a, b);
        
        Assert.IsTrue(equal == expected);
    }
    
    [TestMethod]
    [DataRow(0, 1)]
    [DataRow(1, 0)]
    public void Equals_Invalid(int aSize, int bSize)
    {
        var a = new byte[aSize];
        var b = new byte[bSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.Equals(a, b));
    }
    
    [TestMethod]
    public void Increment_Valid()
    {
        Span<byte> b = stackalloc byte[ChaCha20Poly1305.NonceSize];
        b.Clear();
        
        ConstantTime.Increment(b);
        
        Assert.IsTrue(b[0] == 1);
    }
    
    [TestMethod]
    public void Increment_Invalid()
    {
        var b = Array.Empty<byte>();
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.Increment(b));
    }
    
    [TestMethod]
    [DataRow(true, "")]
    [DataRow(true, "0000")]
    [DataRow(false, "0001")]
    public void IsAllZeros_Valid(bool expected, string buffer)
    {
        Span<byte> b = Convert.FromHexString(buffer);
        
        bool allZeros = ConstantTime.IsAllZeros(b);
        
        Assert.IsTrue(allZeros == expected);
    }
    
    [TestMethod]
    [DataRow("03", "01", "02")]
    [DataRow("03", "02", "01")]
    public void Add_Valid(string buffer, string aString, string bString)
    {
        Span<byte> a = Convert.FromHexString(aString);
        Span<byte> b = Convert.FromHexString(bString);
        Span<byte> buf = stackalloc byte[a.Length];
        
        ConstantTime.Add(buf, a, b);
        
        Assert.AreEqual(buffer, Convert.ToHexString(buf).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(AddSubtractInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Add_Invalid(int bufferSize, int aSize, int bSize)
    {
        var buf = new byte[bufferSize];
        var a = new byte[aSize];
        var b = new byte[bSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.Add(buf, a, b));
    }
    
    [TestMethod]
    [DataRow("01", "02", "01")]
    [DataRow("00", "02", "02")]
    public void Subtract_Valid(string buffer, string aString, string bString)
    {
        Span<byte> a = Convert.FromHexString(aString);
        Span<byte> b = Convert.FromHexString(bString);
        Span<byte> buf = stackalloc byte[a.Length];
        
        ConstantTime.Subtract(buf, a, b);
        
        Assert.AreEqual(buffer, Convert.ToHexString(buf).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(AddSubtractInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Subtract_Invalid(int bufferSize, int aSize, int bSize)
    {
        var buf = new byte[bufferSize];
        var a = new byte[aSize];
        var b = new byte[bSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.Subtract(buf, a, b));
    }
    
    [TestMethod]
    [DataRow(true, "01", "02")]
    [DataRow(false, "02", "01")]
    public void IsLessThan_Valid(bool expected, string aString, string bString)
    {
        Span<byte> a = Convert.FromHexString(aString);
        Span<byte> b = Convert.FromHexString(bString);
        
        bool aLessThan = ConstantTime.IsLessThan(a, b);
        
        Assert.IsTrue(aLessThan == expected);
    }
    
    [TestMethod]
    [DynamicData(nameof(GreaterLessInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void IsLessThan_Invalid(int aSize, int bSize)
    {
        var a = new byte[aSize];
        var b = new byte[bSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.IsLessThan(a, b));
    }
    
    [TestMethod]
    [DataRow(true, "02", "01")]
    [DataRow(false, "01", "02")]
    public void IsGreaterThan_Valid(bool expected, string aString, string bString)
    {
        Span<byte> a = Convert.FromHexString(aString);
        Span<byte> b = Convert.FromHexString(bString);
        
        bool aGreaterThan = ConstantTime.IsGreaterThan(a, b);
        
        Assert.IsTrue(aGreaterThan == expected);
    }
    
    [TestMethod]
    [DynamicData(nameof(GreaterLessInvalidParameterSizes), DynamicDataSourceType.Method)]
    public void IsGreaterThan_Invalid(int aSize, int bSize)
    {
        var a = new byte[aSize];
        var b = new byte[bSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ConstantTime.IsGreaterThan(a, b));
    }
}