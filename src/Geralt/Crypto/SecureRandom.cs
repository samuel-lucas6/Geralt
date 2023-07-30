using System.Globalization;
using System.Text;
using static Interop.Libsodium;

namespace Geralt;

public static class SecureRandom
{
    public const int SeedSize = randombytes_SEEDBYTES;
    public const string AlphabeticChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string NumericChars = "0123456789";
    public const string SymbolChars = "!#$%&'()*+,-./:;<=>?@[]^_`{}~";
    public const string AlphanumericChars = AlphabeticChars + NumericChars;
    public const string AlphanumericSymbolChars = AlphanumericChars + SymbolChars;
    public const int MinUpperBound = 2;
    public const int MinStringLength = 8;
    public const int MaxStringLength = 128;
    public const int MinWordCount = 4;
    public const int MaxWordCount = 20;

    public static unsafe void Fill(Span<byte> buffer)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Sodium.Initialize();
        fixed (byte* b = buffer)
            randombytes_buf(b, (nuint)buffer.Length);
    }

    public static unsafe void FillDeterministic(Span<byte> buffer, ReadOnlySpan<byte> seed)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Validation.EqualToSize(nameof(seed), seed.Length, SeedSize);
        Sodium.Initialize();
        fixed (byte* b = buffer, s = seed)
            randombytes_buf_deterministic(b, (nuint)buffer.Length, s);
    }

    public static int GetInt32(int upperBound)
    {
        Validation.NotLessThanMin(nameof(upperBound), upperBound, MinUpperBound);
        Sodium.Initialize();
        return randombytes_uniform((uint)upperBound);
    }

    public static string GetString(int length, string characterSet = AlphanumericChars)
    {
        Validation.SizeBetween(nameof(length), length, MinStringLength, MaxStringLength);
        Validation.NotNullOrEmpty(nameof(characterSet), characterSet);
        var stringBuilder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            stringBuilder.Append(characterSet[GetInt32(characterSet.Length)]);
        }
        return stringBuilder.ToString();
    }

    public static char[] GetPassphrase(int wordCount, char separatorChar = '-', bool capitalize = false, bool includeNumber = false)
    {
        Validation.SizeBetween(nameof(wordCount), wordCount, MinWordCount, MaxWordCount);
        string[] wordlist = Properties.Resources.wordlist.Split(separator: new[] { "\n" }, StringSplitOptions.RemoveEmptyEntries);
        int numberIndex = 0;
        if (includeNumber) { numberIndex = GetInt32(wordCount); }
        var passphrase = new List<char>();
        for (int i = 0; i < wordCount; i++) {
            int randomIndex = GetInt32(wordlist.Length);
            passphrase.AddRange(capitalize ? CultureInfo.InvariantCulture.TextInfo.ToTitleCase(wordlist[randomIndex]) : wordlist[randomIndex]);
            if (includeNumber && i == numberIndex) { passphrase.Add(char.Parse(GetInt32(NumericChars.Length).ToString())); }
            if (i != wordCount - 1) { passphrase.Add(separatorChar); }
        }
        return passphrase.ToArray();
    }
}
