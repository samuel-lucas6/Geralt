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
        Assert.AreEqual(SecureRandom.MinUpperBound, SecureRandom.MinWordlistSize);
        Assert.AreEqual(4, SecureRandom.MinWordCount);
        Assert.AreEqual(20, SecureRandom.MaxWordCount);
        Assert.AreEqual(9, (int)SecureRandom.LongestWordSize.EffLong);
        Assert.AreEqual(5, (int)SecureRandom.LongestWordSize.EffShort1);
        Assert.AreEqual(10, (int)SecureRandom.LongestWordSize.EffShort2);
        Assert.AreEqual(8, (int)SecureRandom.LongestWordSize.Bip39);
        Assert.AreEqual(8, (int)SecureRandom.LongestWordSize.Slip39);
        Assert.AreEqual(12, (int)SecureRandom.LongestWordSize.Monero);
        Assert.AreEqual(6, (int)SecureRandom.LongestWordSize.Diceware);
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
    [DataRow(SecureRandom.MinWordCount, '-', false, false)]
    [DataRow(SecureRandom.MinWordCount, '_', false, false)]
    [DataRow(SecureRandom.MinWordCount, '.', false, false)]
    [DataRow(SecureRandom.MinWordCount, '?', false, false)]
    [DataRow(SecureRandom.MinWordCount, '+', false, false)]
    [DataRow(SecureRandom.MinWordCount, '$', false, false)]
    [DataRow(SecureRandom.MinWordCount, '&', false, false)]
    [DataRow(SecureRandom.MinWordCount, '©', false, false)]
    [DataRow(SecureRandom.MinWordCount, '"', false, false)]
    [DataRow(SecureRandom.MinWordCount, '(', false, false)]
    [DataRow(SecureRandom.MinWordCount, ')', false, false)]
    [DataRow(SecureRandom.MinWordCount, ' ', true, false)]
    [DataRow(SecureRandom.MinWordCount, ' ', false, true)]
    [DataRow(SecureRandom.MinWordCount, ' ', true, true)]
    public void GeneratePassphrase_Valid(int wordCount, char separatorChar, bool capitalize, bool includeNumber)
    {
        Span<char> buffer = stackalloc char[SecureRandom.GetPassphraseBufferSize((int)SecureRandom.LongestWordSize.EffLong, wordCount)];
        buffer.Clear();

        SecureRandom.GeneratePassphrase(buffer, out int passphraseSize, wordCount, separatorChar, capitalize, includeNumber);
        char[] passphrase = buffer[..passphraseSize].ToArray();
        string[] words = new string(passphrase).Split(separatorChar);

        Assert.HasCount(wordCount, words);
        Assert.AreEqual(wordCount - 1, passphrase.Count(c => c == separatorChar));
        Assert.AreNotEqual(separatorChar, passphrase[^1]);
        foreach (string word in words) {
            Assert.AreEqual(capitalize, char.IsUpper(word[0]));
            Assert.AreEqual(word.Length, word.Count(char.IsAsciiLetterOrDigit));
        }
        Assert.AreEqual(includeNumber ? 1 : 0, passphrase.Count(char.IsDigit));
        Assert.IsFalse(passphrase.Any(c => c is '\0' or '\r' or '\n'));
        Assert.IsTrue(buffer[passphraseSize..].SequenceEqual(new char[buffer.Length - passphraseSize]));
    }

    [TestMethod]
    [DataRow(8, new string[0], SecureRandom.MinWordCount, '-')]
    [DataRow(20, new[] { "able" }, SecureRandom.MinWordCount, '-')]
    [DataRow(20, new[] { "able", "zoom" }, SecureRandom.MinWordCount, '\0')]
    [DataRow(20, new[] { "able", "zoom" }, SecureRandom.MinWordCount, '\r')]
    [DataRow(20, new[] { "able", "zoom" }, SecureRandom.MinWordCount, '\n')]
    [DataRow(8, new[] { "", "" }, SecureRandom.MinWordCount, '-')]
    [DataRow(20, new[] { " ", "able" }, SecureRandom.MinWordCount, '-')]
    [DataRow(20, new[] { "able", " " }, SecureRandom.MinWordCount, '-')]
    [DataRow(20, new[] { "\n", "able" }, SecureRandom.MinWordCount, '-')]
    [DataRow(20, new[] { "\0", "able" }, SecureRandom.MinWordCount, '-')]
    [DataRow(105, new[] { "able", "zoom" }, SecureRandom.MaxWordCount + 1, '-')]
    [DataRow(15, new[] { "able", "zoom" }, SecureRandom.MinWordCount - 1, '-')]
    [DataRow(20 + 1, new[] { "able", "zoom" }, SecureRandom.MinWordCount, '-')]
    [DataRow(20 - 1, new[] { "able", "zoom" }, SecureRandom.MinWordCount, '-')]
    public void GeneratePassphrase_Invalid(int bufferSize, string[] wordlist, int wordCount, char separatorChar)
    {
        var invalidChars = SearchValues.Create([' ', '\0', '\r', '\n']);
        var word1 = wordlist.Length > 0 ? wordlist[0] : ReadOnlySpan<char>.Empty;
        var word2 = wordlist.Length > 1 ? wordlist[1] : ReadOnlySpan<char>.Empty;
        var buffer = new char[bufferSize];

        if (word1.ContainsAny(invalidChars) || word2.ContainsAny(invalidChars)) {
            Assert.ThrowsExactly<FormatException>(() => SecureRandom.GeneratePassphrase(buffer, passphraseSize: out _, wordlist, wordCount, separatorChar));
        }
        else {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => SecureRandom.GeneratePassphrase(buffer, passphraseSize: out _, wordlist, wordCount, separatorChar));
        }
    }

    [TestMethod]
    [DataRow(8, SecureRandom.MinLongestWordSize, SecureRandom.MinWordCount)]
    [DataRow(40, SecureRandom.MinLongestWordSize, SecureRandom.MaxWordCount)]
    [DataRow(184, SecureRandom.MaxLongestWordSize, SecureRandom.MinWordCount)]
    [DataRow(920, SecureRandom.MaxLongestWordSize, SecureRandom.MaxWordCount)]
    public void GetPassphraseBufferSize_Valid(int bufferSize, int longestWord, int wordCount)
    {
        int size = SecureRandom.GetPassphraseBufferSize(longestWord, wordCount);

        Assert.AreEqual(bufferSize, size);
    }

    [TestMethod]
    [DataRow(SecureRandom.MaxLongestWordSize + 1, SecureRandom.MinWordCount)]
    [DataRow(SecureRandom.MinLongestWordSize - 1, SecureRandom.MinWordCount)]
    [DataRow((int)SecureRandom.LongestWordSize.EffLong, SecureRandom.MaxWordCount + 1)]
    [DataRow((int)SecureRandom.LongestWordSize.EffLong, SecureRandom.MinWordCount - 1)]
    public void GetPassphraseBufferSize_Invalid(int longestWord, int wordCount)
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => SecureRandom.GetPassphraseBufferSize(longestWord, wordCount));
    }

    [TestMethod]
    public void GetWordlist_Valid()
    {
        var invalidChars = SearchValues.Create([' ', '\0', '\r', '\n']);
        var numericChars = SearchValues.Create(SecureRandom.NumericChars);
        var symbolChars = SearchValues.Create(SecureRandom.SymbolChars);

        ReadOnlySpan<string> wordlist = SecureRandom.GetWordlist();

        // EFF's Long Wordlist is 7776 words, but I've removed hyphenated words
        Assert.AreEqual(7772, wordlist.Length);
        Assert.AreEqual("abacus", wordlist[0]);
        Assert.AreEqual("zoom", wordlist[^1]);
        foreach (ReadOnlySpan<char> word in wordlist) {
            Assert.IsFalse(word.IsEmpty);
            Assert.IsFalse(word.ContainsAny(invalidChars));
            Assert.IsFalse(word.ContainsAny(numericChars));
            Assert.IsFalse(word.ContainsAny(symbolChars));
        }
    }
}
