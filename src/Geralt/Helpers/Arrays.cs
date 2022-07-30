namespace Geralt;

public static class Arrays
{
    public static T[] Concat<T>(params T[][] arrays)
    {
        int offset = 0;
        var result = new T[arrays.Sum(array => array.Length)];
        foreach (var array in arrays)
        {
            Array.Copy(array, sourceIndex: 0, result, offset, array.Length);
            offset += array.Length;
        }
        return result;
    }
    
    public static byte[] Slice(byte[] sourceArray, int sourceIndex, int length)
    {
        var destinationArray = new byte[length];
        Array.Copy(sourceArray, sourceIndex, destinationArray, destinationIndex: 0, destinationArray.Length);
        return destinationArray;
    }
}