using System.Text;
using System.Globalization;
using static Interop.Libsodium;

namespace Geralt;

public static class SecureRandom
{
    public const int SeedSize = randombytes_SEEDBYTES;
    public const string AlphabeticChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string NumericChars = "0123456789";
    public const string SymbolChars = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    public const string AlphanumericChars = AlphabeticChars + NumericChars;
    public const string AlphanumericSymbolChars = AlphanumericChars + SymbolChars;
    public const int MinUpperBound = 2;
    public const int MinStringSize = 8;
    public const int MaxStringSize = 128;
    public const int MinCharacterSetSize = MinUpperBound;
    public const int MinLongestWordSize = 1; // Shortest word in the English dictionary
    public const int MaxLongestWordSize = 45; // Longest word in the English dictionary
    public const int MinWordlistSize = MinUpperBound;
    public const int MinWordCount = 4;
    public const int MaxWordCount = 20;

    // https://www.browserling.com/tools/longest-line
    public enum LongestWordSize
    {
        EffLong = 9, // https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
        EffShort1 = 5, // https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt
        EffShort2 = 10, // https://www.eff.org/files/2016/09/08/eff_short_wordlist_2_0.txt
        Bip39 = 8, // https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
        Slip39 = 8, // https://github.com/satoshilabs/slips/blob/master/slip-0039/wordlist.txt
        Monero = 12, // https://github.com/monero-project/monero/blob/master/src/mnemonics/english.h
        Diceware = 6 // https://theworld.com/~reinhold/diceware.html (both 7776 and 8192 words)
        // Other wordlists: https://gist.github.com/atoponce/95c4f36f2bc12ec13242a3ccc55023af
    }

    public static void Fill(Span<byte> buffer)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Sodium.Initialize();
        randombytes_buf(buffer, (nuint)buffer.Length);
    }

    public static void FillDeterministic(Span<byte> buffer, ReadOnlySpan<byte> seed)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Validation.EqualToSize(nameof(seed), seed.Length, SeedSize);
        Sodium.Initialize();
        randombytes_buf_deterministic(buffer, (nuint)buffer.Length, seed);
    }

    public static int GetInt32(int upperBound)
    {
        Validation.NotLessThanMin(nameof(upperBound), upperBound, MinUpperBound);
        Sodium.Initialize();
        return randombytes_uniform((uint)upperBound);
    }

    public static void GenerateString(Span<char> buffer, ReadOnlySpan<char> characterSet)
    {
        Validation.SizeBetween(nameof(buffer), buffer.Length, MinStringSize, MaxStringSize);
        Validation.NotLessThanMin(nameof(characterSet), characterSet.Length, MinCharacterSetSize);
        for (int i = 0; i < buffer.Length; i++) {
            buffer[i] = characterSet[GetInt32(characterSet.Length)];
        }
    }

    public static void GeneratePassphrase(Span<char> buffer, out int passphraseSize, ReadOnlySpan<string> wordlist, int wordCount, char separatorChar = '-', bool capitalize = false, bool includeNumber = false)
    {
        Validation.NotLessThanMin(nameof(wordlist), wordlist.Length, MinWordlistSize);
        if (CharUnicodeInfo.GetUnicodeCategory(separatorChar) is UnicodeCategory.NonSpacingMark or UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator
            or UnicodeCategory.ParagraphSeparator or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned) {
            throw new ArgumentOutOfRangeException(nameof(separatorChar), separatorChar, $"{nameof(separatorChar)} must be a printable character.");
        }
        int longestWord = 0;
        foreach (ReadOnlySpan<char> word in wordlist) {
            if (word.IsEmpty) {
                throw new ArgumentOutOfRangeException(nameof(wordlist), $"{nameof(wordlist)} must not contain empty words.");
            }
            foreach (var rune in word.EnumerateRunes()) {
                if (rune == Rune.ReplacementChar || Rune.GetUnicodeCategory(rune) is UnicodeCategory.SpaceSeparator or UnicodeCategory.Control or UnicodeCategory.Format
                    or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned) {
                    throw new FormatException($"{nameof(wordlist)} must only contain printable characters, excluding spaces.");
                }
            }
            if (word.Length > longestWord) {
                longestWord = word.Length;
            }
        }
        Validation.EqualToSize(nameof(buffer), buffer.Length, GetPassphraseBufferSize(longestWord, wordCount));
        int numberIndex = 0;
        if (includeNumber) { numberIndex = GetInt32(wordCount); }
        int bufferIndex = 0;
        for (int i = 0; i < wordCount; i++) {
            int wordIndex = bufferIndex;
            int randomIndex = GetInt32(wordlist.Length);
            foreach (char c in wordlist[randomIndex]) {
                if (capitalize && bufferIndex == wordIndex) {
                    buffer[bufferIndex++] = char.ToUpperInvariant(c);
                    continue;
                }
                buffer[bufferIndex++] = c;
            }
            if (includeNumber && i == numberIndex) {
                buffer[bufferIndex++] = (char)('0' + GetInt32(NumericChars.Length));
            }
            if (i != wordCount - 1) {
                buffer[bufferIndex++] = separatorChar;
            }
        }
        passphraseSize = bufferIndex;
    }

    public static void GeneratePassphrase(Span<char> buffer, out int passphraseSize, int wordCount, char separatorChar = '-', bool capitalize = false, bool includeNumber = false)
    {
        // The default wordlist is EFF's Long Wordlist with hyphenated words removed, leaving 7772 words
        ReadOnlySpan<string> effLongWordlist = GetWordlist();
        GeneratePassphrase(buffer, out passphraseSize, effLongWordlist, wordCount, separatorChar, capitalize, includeNumber);
    }

    public static int GetPassphraseBufferSize(int longestWord, int wordCount)
    {
        Validation.SizeBetween(nameof(longestWord), longestWord, MinLongestWordSize, MaxLongestWordSize);
        Validation.SizeBetween(nameof(wordCount), wordCount, MinWordCount, MaxWordCount);
        // Need to account for the separator chars and a number
        return (longestWord * wordCount) + wordCount;
    }

    public static ReadOnlySpan<string> GetWordlist()
    {
        return Properties.Resources.wordlist.ReplaceLineEndings().Split(separator: Environment.NewLine, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
