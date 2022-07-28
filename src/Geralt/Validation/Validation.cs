namespace Geralt;

internal static class Validation
{
    internal static void EqualToSize(string paramName, int size, int validSize)
    {
        if (size != validSize)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} must be {size} bytes long.");
    }

    internal static void SizeBetween(string paramName, int size, int minSize, int maxSize)
    {
        if (size < minSize || size > maxSize)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} must be between {minSize} and {maxSize} bytes long.");
    }

    internal static void GreaterThanZero(string paramName, int size)
    {
        if (size <= 0)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} must be greater than 0.");
    }

    internal static void NotLessThanMin(string paramName, int size, int minSize)
    {
        if (size < minSize)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} must be equal to or greater than {minSize}.");
    }

    internal static void NotEmpty(string paramName, int size)
    {
        if (size == 0)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} cannot have a length of 0.");
    }

    internal static void NotNullOrEmpty(string paramName, string value)
    {
        if (value == null)
            throw new ArgumentNullException(paramName, $"{paramName} cannot be null.");
        if (value.Length == 0)
            throw new ArgumentOutOfRangeException(paramName, $"{paramName} cannot be empty.");
    }
}