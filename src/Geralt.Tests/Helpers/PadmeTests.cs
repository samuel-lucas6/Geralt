namespace Geralt.Tests;

[TestClass]
public class PadmeTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return [(ulong)0, (ulong)0];
        yield return [(ulong)1, (ulong)1];
        yield return [(ulong)2, (ulong)2];
        yield return [(ulong)3, (ulong)3];
        yield return [(ulong)7, (ulong)7];
        yield return [(ulong)8, (ulong)8];
        yield return [(ulong)10, (ulong)9];
        yield return [(ulong)16, (ulong)15];
        yield return [(ulong)16, (ulong)16];
        yield return [(ulong)18, (ulong)17];
        yield return [(ulong)32, (ulong)31];
        yield return [(ulong)32, (ulong)32];
        yield return [(ulong)36, (ulong)33];
        yield return [(ulong)64, (ulong)63];
        yield return [(ulong)64, (ulong)64];
        yield return [(ulong)72, (ulong)65];
        yield return [(ulong)104, (ulong)99];
        yield return [(ulong)104, (ulong)100];
        yield return [(ulong)128, (ulong)127];
        yield return [(ulong)128, (ulong)128];
        yield return [(ulong)144, (ulong)129];
        yield return [(ulong)256, (ulong)255];
        yield return [(ulong)256, (ulong)256];
        yield return [(ulong)272, (ulong)257];
        yield return [(ulong)512, (ulong)511];
        yield return [(ulong)512, (ulong)512];
        yield return [(ulong)544, (ulong)513];
        yield return [(ulong)1024, (ulong)999];
        yield return [(ulong)1024, (ulong)1000];
        yield return [(ulong)1024, (ulong)1023];
        yield return [(ulong)1024, (ulong)1024];
        yield return [(ulong)1088, (ulong)1025];
        yield return [(ulong)12800, (ulong)12345];
        yield return [(ulong)65536, (ulong)65535];
        yield return [(ulong)65536, (ulong)65536];
        yield return [(ulong)67584, (ulong)65537];
        yield return [(ulong)1015808, (ulong)1000000];
        yield return [(ulong)10223616, (ulong)10000000];
        yield return [(ulong)16777216, (ulong)16777216];
        yield return [(ulong)17301504, (ulong)16777217];
        yield return [(ulong)2147483648, (ulong)2147483647];
        yield return [(ulong)2147483648, (ulong)2147483648];
        yield return [(ulong)2214592512, (ulong)2147483649];
        yield return [(ulong)4294967296, (ulong)4294967296];
        yield return [(ulong)4362076160, (ulong)4294967297];
        yield return [(ulong)1099511627776, (ulong)1099511627776];
        yield return [(ulong)1116691496960, (ulong)1099511640121];
        yield return [(ulong)281474976710656, (ulong)281474976710656];
        yield return [(ulong)285873023221760, (ulong)281474976710657];
        yield return [(ulong)72057594037927936, (ulong)72057594037927936];
        yield return [(ulong)73183493944770560, (ulong)72057594037927937];
        yield return [(ulong)9151314442816847872, (ulong)9151314442816847872];
        yield return [(ulong)9223372036854775808, (ulong)9151314442816847873];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ulong.MaxValue - (1UL << 57) + 2];
        yield return [ulong.MaxValue];
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors))]
    public void GetPaddedLength_Valid(ulong paddedLength, ulong length)
    {
        ulong pl = Padme.GetPaddedLength(length);

        Assert.AreEqual(paddedLength, pl);
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes))]
    public void GetPaddedLength_Invalid(ulong length)
    {
        Assert.ThrowsExactly<OverflowException>(() => Padme.GetPaddedLength(length));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors))]
    public void GetPaddingLength_Valid(ulong paddedLength, ulong length)
    {
        ulong pl = Padme.GetPaddingLength(length);

        Assert.AreEqual(paddedLength - length, pl);
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes))]
    public void GetPaddingLength_Invalid(ulong length)
    {
        Assert.ThrowsExactly<OverflowException>(() => Padme.GetPaddingLength(length));
    }
}
