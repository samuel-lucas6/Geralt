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
    public void Concat_Empty_Valid()
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

            parameters[1] = [0x01, 0x02, 0x03, 0x04];
            buffer = new byte[parameters[1].Length];
        }
    }

    [TestMethod]
    public void Concat_Invalid()
    {
        var parameters = new List<byte[]>
        {
            new byte[] { 0x01, 0x02, 0x03, 0x04 }
        };

        for (int i = 0; i < 5; i++) {
            parameters.Add(parameters[0]);
            var buffer = new byte[parameters.Count * parameters[0].Length];
            var biggerBuffer = new byte[buffer.Length + 1];
            var smallerBuffer = new byte[buffer.Length - 1];
            switch (parameters.Count) {
                case 2:
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(biggerBuffer, parameters[0], parameters[1]));
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(smallerBuffer, parameters[0], parameters[1]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, buffer.AsSpan()[..(buffer.Length / 2)], parameters[1]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], buffer.AsSpan()[..(buffer.Length / 2)]));
                    break;
                case 3:
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(biggerBuffer, parameters[0], parameters[1], parameters[2]));
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(smallerBuffer, parameters[0], parameters[1], parameters[2]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, buffer.AsSpan()[..(buffer.Length / 3)], parameters[1], parameters[2]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], buffer.AsSpan()[..(buffer.Length / 3)], parameters[2]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], buffer.AsSpan()[..(buffer.Length / 3)]));
                    break;
                case 4:
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(biggerBuffer, parameters[0], parameters[1], parameters[2], parameters[3]));
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(smallerBuffer, parameters[0], parameters[1], parameters[2], parameters[3]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, buffer.AsSpan()[..(buffer.Length / 4)], parameters[1], parameters[2], parameters[3]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], buffer.AsSpan()[..(buffer.Length / 4)], parameters[2], parameters[3]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], buffer.AsSpan()[..(buffer.Length / 4)], parameters[3]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], parameters[2], buffer.AsSpan()[..(buffer.Length / 4)]));
                    break;
                case 5:
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(biggerBuffer, parameters[0], parameters[1], parameters[2], parameters[3], parameters[4]));
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(smallerBuffer, parameters[0], parameters[1], parameters[2], parameters[3], parameters[4]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, buffer.AsSpan()[..(buffer.Length / 5)], parameters[1], parameters[2], parameters[3], parameters[4]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], buffer.AsSpan()[..(buffer.Length / 5)], parameters[2], parameters[3], parameters[4]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], buffer.AsSpan()[..(buffer.Length / 5)], parameters[3], parameters[4]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], parameters[2], buffer.AsSpan()[..(buffer.Length / 5)], parameters[4]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], parameters[2], parameters[3], buffer.AsSpan()[..(buffer.Length / 5)]));
                    break;
                case 6:
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(biggerBuffer, parameters[0], parameters[1], parameters[2], parameters[3], parameters[4], parameters[5]));
                    Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Spans.Concat(smallerBuffer, parameters[0], parameters[1], parameters[2], parameters[3], parameters[4], parameters[5]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, buffer.AsSpan()[..(buffer.Length / 6)], parameters[1], parameters[2], parameters[3], parameters[4], parameters[5]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], buffer.AsSpan()[..(buffer.Length / 6)], parameters[2], parameters[3], parameters[4], parameters[5]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], buffer.AsSpan()[..(buffer.Length / 6)], parameters[3], parameters[4], parameters[5]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], parameters[2], buffer.AsSpan()[..(buffer.Length / 6)], parameters[4], parameters[5]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], parameters[2], parameters[3], buffer.AsSpan()[..(buffer.Length / 6)], parameters[5]));
                    Assert.ThrowsExactly<ArgumentException>(() => Spans.Concat(buffer, parameters[0], parameters[1], parameters[2], parameters[3], parameters[4], buffer.AsSpan()[..(buffer.Length / 6)]));
                    break;
            }
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
