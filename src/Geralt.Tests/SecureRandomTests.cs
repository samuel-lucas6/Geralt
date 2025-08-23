using System.Buffers;

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
        Assert.AreEqual("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", SecureRandom.SymbolChars);
        Assert.AreEqual(SecureRandom.AlphabeticChars + SecureRandom.NumericChars, SecureRandom.AlphanumericChars);
        Assert.AreEqual(SecureRandom.AlphanumericChars + SecureRandom.SymbolChars, SecureRandom.AlphanumericSymbolChars);
        Assert.AreEqual(2, SecureRandom.MinUpperBound);
        Assert.AreEqual(8, SecureRandom.MinStringSize);
        Assert.AreEqual(SecureRandom.MinUpperBound, SecureRandom.MinCharacterSetSize);
        Assert.AreEqual(128, SecureRandom.MaxStringSize);
        Assert.AreEqual(1, SecureRandom.MinLongestWordSize);
        Assert.AreEqual(45, SecureRandom.MaxLongestWordSize);
        Assert.AreEqual(9, SecureRandom.LongestWordSize);
        Assert.AreEqual(SecureRandom.MinUpperBound, SecureRandom.MinWordlistSize);
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

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => SecureRandom.Fill(buffer));
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

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => SecureRandom.FillDeterministic(buffer, seed));
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

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => SecureRandom.GetInt32(upperBound));
    }

    [TestMethod]
    public void GenerateString_Valid()
    {
        Span<char> buffer = stackalloc char[SecureRandom.MinStringSize];
        ReadOnlySpan<char> characterSet = SecureRandom.AlphabeticChars;

        SecureRandom.GenerateString(buffer, characterSet);

        foreach (char c in buffer) {
            Assert.IsTrue(characterSet.Contains(c));
        }
    }

    [TestMethod]
    [DataRow(SecureRandom.MaxStringSize + 1, SecureRandom.MinCharacterSetSize)]
    [DataRow(SecureRandom.MinStringSize - 1, SecureRandom.MinCharacterSetSize)]
    [DataRow(SecureRandom.MinStringSize, SecureRandom.MinCharacterSetSize - 1)]
    [DataRow(SecureRandom.MinStringSize, 0)]
    public void GenerateString_Invalid(int bufferSize, int characterSetSize)
    {
        var buffer = new char[bufferSize];
        var characterSet = new char[characterSetSize];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => SecureRandom.GenerateString(buffer, characterSet));
    }

    [TestMethod]
    [DataRow(SecureRandom.MinWordCount, ' ', false, false)]
    [DataRow(SecureRandom.MaxWordCount, ' ', false, false)]
    [DataRow(SecureRandom.MinWordCount, '_', false, false)]
    [DataRow(SecureRandom.MinWordCount, ' ', true, false)]
    [DataRow(SecureRandom.MinWordCount, ' ', false, true)]
    [DataRow(SecureRandom.MinWordCount, ' ', true, true)]
    public void GeneratePassphrase_Valid(int wordCount, char separatorChar, bool capitalize, bool includeNumber)
    {
        Span<char> buffer = stackalloc char[SecureRandom.GetPassphraseBufferSize(SecureRandom.LongestWordSize, wordCount)];
        buffer.Clear();

        int passphraseSize = SecureRandom.GeneratePassphrase(buffer, wordCount, separatorChar, capitalize, includeNumber);
        var passphrase = buffer[..passphraseSize].ToArray();

        Assert.AreEqual(wordCount - 1, passphrase.Count(c => c == separatorChar));
        Assert.AreNotEqual(separatorChar, passphrase[^1]);
        Assert.AreEqual(capitalize, char.IsUpper(passphrase[0]));
        Assert.AreEqual(capitalize ? wordCount : 0, passphrase.Count(char.IsUpper));
        Assert.AreEqual(includeNumber ? 1 : 0, passphrase.Count(char.IsDigit));
        Assert.IsFalse(passphrase.Any(c => c is '\0' or '\r' or '\n'));
        Assert.IsTrue(buffer[passphraseSize..].SequenceEqual(new char[buffer.Length - passphraseSize]));
    }

    [TestMethod]
    [DataRow(1, SecureRandom.MinWordlistSize, SecureRandom.MaxWordCount, '-')]
    [DataRow(-1, SecureRandom.MinWordlistSize, SecureRandom.MaxWordCount, '-')]
    [DataRow(0, SecureRandom.MinWordlistSize - 1, SecureRandom.MaxWordCount, '-')]
    [DataRow(0, 0, SecureRandom.MaxWordCount, '-')]
    [DataRow(0, null, SecureRandom.MaxWordCount, '-')]
    [DataRow(0, SecureRandom.MinWordlistSize, SecureRandom.MaxWordCount + 1, '-')]
    [DataRow(0, SecureRandom.MinWordlistSize, SecureRandom.MinWordCount - 1, '-')]
    [DataRow(0, SecureRandom.MinWordlistSize, SecureRandom.MinWordCount, '\0')]
    [DataRow(0, SecureRandom.MinWordlistSize, SecureRandom.MinWordCount, '\r')]
    [DataRow(0, SecureRandom.MinWordlistSize, SecureRandom.MinWordCount, '\n')]
    public void GeneratePassphrase_Invalid(int bufferSizeAdjustment, int? wordlistSize, int wordCount, char separatorChar)
    {
        int bufferSize = SecureRandom.LongestWordSize * wordCount + (wordCount - 1);
        var buffer = new char[bufferSize + bufferSizeAdjustment];
        string[] wordlist = wordlistSize switch {
            null => [null!, null!],
            SecureRandom.MinWordlistSize => ["test1", "test2"],
            _ => ["test1"]
        };

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => SecureRandom.GeneratePassphrase(buffer, wordlist, wordCount, separatorChar));
        if (separatorChar is '\0' or '\r' or '\n') {
            string invalidChar = separatorChar.ToString();
            Assert.ThrowsExactly<FormatException>(() => SecureRandom.GeneratePassphrase(buffer, new[] {invalidChar, invalidChar}, wordCount));
        }
    }

    [TestMethod]
    [DataRow(8, 1, SecureRandom.MinWordCount)]
    [DataRow(184, 45, SecureRandom.MinWordCount)]
    [DataRow(40, 1, SecureRandom.MaxWordCount)]
    [DataRow(920, 45, SecureRandom.MaxWordCount)]
    public void GetPassphraseBufferSize_Valid(int bufferSize, int longestWord, int wordCount)
    {
        int size = SecureRandom.GetPassphraseBufferSize(longestWord, wordCount);

        Assert.AreEqual(bufferSize, size);
    }

    [TestMethod]
    [DataRow(SecureRandom.MaxLongestWordSize + 1, SecureRandom.MinWordCount)]
    [DataRow(SecureRandom.MinLongestWordSize - 1, SecureRandom.MinWordCount)]
    [DataRow(SecureRandom.LongestWordSize, SecureRandom.MaxWordCount + 1)]
    [DataRow(SecureRandom.LongestWordSize, SecureRandom.MinWordCount - 1)]
    public void GetPassphraseBufferSize_Invalid(int longestWord, int wordCount)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => SecureRandom.GetPassphraseBufferSize(longestWord, wordCount));
    }

    [TestMethod]
    public void GetWordlist_Valid()
    {
        var invalidChars = SearchValues.Create([' ', '\0', '\r', '\n']);
        var symbolChars = SearchValues.Create(SecureRandom.SymbolChars);

        ReadOnlySpan<string> wordlist = SecureRandom.GetWordlist();

        // EFF's long wordlist is 7776, but I've removed hyphenated words
        Assert.AreEqual(7772, wordlist.Length);
        Assert.AreEqual("abacus", wordlist[0]);
        Assert.AreEqual("zoom", wordlist[^1]);
        foreach (ReadOnlySpan<char> word in wordlist) {
            Assert.IsFalse(word.IsEmpty);
            Assert.IsFalse(word.ContainsAny(invalidChars));
            Assert.IsFalse(word.ContainsAny(symbolChars));
        }
    }
}
