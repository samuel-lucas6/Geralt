namespace Geralt.Tests;

[TestClass]
public class SecureMemoryTests
{
    [TestMethod]
    [DataRow(0)]
    [DataRow(ChaCha20.KeySize)]
    public void ZeroMemory_Bytes_Valid(int bufferSize)
    {
        Span<byte> b = stackalloc byte[bufferSize];
        RandomNumberGenerator.Fill(b);

        SecureMemory.ZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new byte[b.Length]));
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(SecureRandom.MinStringSize)]
    public void ZeroMemory_Chars_Valid(int bufferSize)
    {
        Span<char> b = stackalloc char[bufferSize];
        b.Fill('a');

        SecureMemory.ZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new char[b.Length]));
    }

    [TestMethod]
    public void ZeroMemory_String_Valid()
    {
        ReadOnlySpan<char> s = RandomNumberGenerator.GetString(SecureRandom.AlphanumericSymbolChars, SecureRandom.MinStringSize).AsSpan();

        SecureMemory.ZeroMemory(s);

        Assert.IsTrue(s.SequenceEqual(new char[s.Length]));
        // Not the same as null or string.Empty
        Assert.IsTrue(s.ToString().All(c => c == '\0'));
    }
}
