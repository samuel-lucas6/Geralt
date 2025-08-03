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
    public const int MinLongestWordSize = 1;
    public const int MaxLongestWordSize = 45; // Longest word in the English dictionary
    public const int LongestWordSize = 9;
    public const int MinWordlistSize = MinUpperBound;
    public const int MinWordCount = 4;
    public const int MaxWordCount = 20;

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

    public static int GeneratePassphrase(Span<char> buffer, ReadOnlySpan<string> wordlist, int wordCount, char separatorChar = '-', bool capitalize = false, bool includeNumber = false)
    {
        Validation.NotLessThanMin(nameof(wordlist), wordlist.Length, MinWordlistSize);
        if (char.IsControl(separatorChar)) {
            throw new ArgumentOutOfRangeException(nameof(separatorChar), separatorChar, $"{nameof(separatorChar)} must not be a control character.");
        }
        int longestWord = 0;
        ReadOnlySpan<char> invalidChars = [' ', '\0', '\r', '\n'];
        foreach (ReadOnlySpan<char> word in wordlist) {
            Validation.NotEmpty(nameof(word), word.Length);
            if (word.ContainsAny(invalidChars)) {
                throw new FormatException($"{nameof(wordlist)} must not contain whitespace, null, or newline characters.");
            }
            if (word.Length > longestWord) {
                longestWord = word.Length;
            }
        }
        Validation.EqualToSize(nameof(buffer), buffer.Length, GetPassphraseBufferSize(longestWord, wordCount, includeNumber));
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
        return bufferIndex;
    }

    public static int GeneratePassphrase(Span<char> buffer, int wordCount, char separatorChar = '-', bool capitalize = false, bool includeNumber = false)
    {
        ReadOnlySpan<string> wordlist = GetWordlist();
        return GeneratePassphrase(buffer, wordlist, wordCount, separatorChar, capitalize, includeNumber);
    }

    public static int GetPassphraseBufferSize(int longestWord, int wordCount, bool includeNumber)
    {
        Validation.SizeBetween(nameof(longestWord), longestWord, MinLongestWordSize, MaxLongestWordSize);
        Validation.SizeBetween(nameof(wordCount), wordCount, MinWordCount, MaxWordCount);
        // Need to account for the separator chars and number
        return longestWord * wordCount + (includeNumber ? wordCount : wordCount - 1);
    }

    public static ReadOnlySpan<string> GetWordlist()
    {
        return Properties.Resources.wordlist.ReplaceLineEndings().Split(separator: Environment.NewLine, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
