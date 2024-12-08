namespace Geralt.Tests;

[TestClass]
public class SecureMemoryTests
{
    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(Environment.SystemPageSize, SecureMemory.PageSize);
    }

    [TestMethod]
    public void ZeroMemory_Bytes_Valid()
    {
        Span<byte> b = stackalloc byte[ChaCha20.KeySize];
        RandomNumberGenerator.Fill(b);

        SecureMemory.ZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new byte[b.Length]));
    }

    [TestMethod]
    public void ZeroMemory_Bytes_Invalid()
    {
        var b = Array.Empty<byte>();

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.ZeroMemory(b));
    }

    [TestMethod]
    public void ZeroMemory_Chars_Valid()
    {
        Span<char> b = stackalloc char[SecureRandom.MinStringLength];
        b.Fill('a');

        SecureMemory.ZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new char[b.Length]));
    }

    [TestMethod]
    public void ZeroMemory_Chars_Invalid()
    {
        var b = Array.Empty<char>();

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.ZeroMemory(b));
    }

    [TestMethod]
    public void ZeroMemory_String_Valid()
    {
        ReadOnlySpan<char> s = RandomNumberGenerator.GetString(SecureRandom.AlphanumericSymbolChars, SecureRandom.MinStringLength).AsSpan();

        SecureMemory.ZeroMemory(s);

        Assert.IsTrue(s.SequenceEqual(new char[s.Length]));
        // Not the same as null or string.Empty
        Assert.IsTrue(s.ToString().All(c => c == '\0'));
    }

    [TestMethod]
    public void ZeroMemory_String_Invalid()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.ZeroMemory(string.Empty.AsSpan()));
    }

    [TestMethod]
    public void LockMemory_UnlockAndZeroMemory_Valid()
    {
        Span<byte> b = stackalloc byte[SecureMemory.PageSize];
        Span<byte> c = stackalloc byte[b.Length];
        RandomNumberGenerator.Fill(b);
        b.CopyTo(c);

        SecureMemory.LockMemory(b);

        Assert.IsTrue(b.SequenceEqual(c));

        SecureMemory.UnlockAndZeroMemory(b);

        Assert.IsTrue(b.SequenceEqual(new byte[b.Length]));
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(4096 + 1)]
    [DataRow(4096 - 1)]
    [DataRow(8192 + 1)]
    [DataRow(8192 - 1)]
    public void LockMemory_UnlockAndZeroMemory_Invalid(int bufferSize)
    {
        var b = new byte[bufferSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.LockMemory(b));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => SecureMemory.UnlockAndZeroMemory(b));
    }

    [TestMethod]
    public void LockMemory_UnlockAndZeroMemory_InvalidOperation()
    {
        var b = new byte[SecureMemory.PageSize * 131072];

        Assert.ThrowsException<OutOfMemoryException>(() => SecureMemory.LockMemory(b));
        // This test fails on Linux/macOS - munlock() must not return an error despite no locking taking place
        if (OperatingSystem.IsWindows()) {
            Assert.ThrowsException<InvalidOperationException>(() => SecureMemory.UnlockAndZeroMemory(b));
        }
    }
}
