using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Geralt.Tests;

[TestClass]
public class SpansTests
{
    [TestMethod]
    public void Concat_Valid()
    {
        var parameters = new List<byte[]>
        {
            new byte[] { 0x01, 0x02, 0x03, 0x04 }
        };
        
        for (int i = 0; i < 5; i++) {
            parameters.Add(parameters[0]);
            Span<byte> buffer = new byte[parameters.Count * parameters[0].Length];
            Span<byte> expected = new byte[buffer.Length];
            switch (parameters.Count) {
                case 2:
                    Spans.Concat(buffer, parameters[0], parameters[1]);
                    expected = Concat(parameters[0], parameters[1]);
                    break;
                case 3:
                    Spans.Concat(buffer, parameters[0], parameters[1], parameters[2]);
                    expected = Concat(parameters[0], parameters[1], parameters[2]);
                    break;
                case 4:
                    Spans.Concat(buffer, parameters[0], parameters[1], parameters[2], parameters[3]);
                    expected = Concat(parameters[0], parameters[1], parameters[2], parameters[3]);
                    break;
                case 5:
                    Spans.Concat(buffer, parameters[0], parameters[1], parameters[2], parameters[3], parameters[4]);
                    expected = Concat(parameters[0], parameters[1], parameters[2], parameters[3], parameters[4]);
                    break;
                case 6:
                    Spans.Concat(buffer, parameters[0], parameters[1], parameters[2], parameters[3], parameters[4], parameters[5]);
                    expected = Concat(parameters[0], parameters[1], parameters[2], parameters[3], parameters[4], parameters[5]);
                    break;
            }
            Assert.IsTrue(buffer.SequenceEqual(expected));
        }
    }
    
    [TestMethod]
    public void ConcatEmpty_Valid()
    {
        var buffer = Span<byte>.Empty;
        var parameters = new List<byte[]>
        {
            Array.Empty<byte>(),
            Array.Empty<byte>()
        };
        
        for (int i = 0; i < 2; i++) {
            Spans.Concat(buffer, parameters[0], parameters[1]);
            Span<byte> expected = Concat(parameters[0], parameters[1]);
            
            Assert.IsTrue(buffer.SequenceEqual(expected));
            
            parameters[1] = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            buffer = new byte[parameters[1].Length];
        }
    }
    
    private static T[] Concat<T>(params T[][] arrays)
    {
        int offset = 0;
        var result = new T[arrays.Sum(array => array.Length)];
        foreach (var array in arrays) {
            Array.Copy(array, sourceIndex: 0, result, offset, array.Length);
            offset += array.Length;
        }
        return result;
    }
}