namespace Geralt;

public static class Validation
{
    public static void EqualToSize(string paramName, int size, int validSize)
    {
        if (size != validSize)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} must be {validSize} bytes long.");
    }

    public static void SizeBetween(string paramName, int size, int minSize, int maxSize)
    {
        if (size < minSize || size > maxSize)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} must be between {minSize} and {maxSize} bytes long.");
    }

    public static void GreaterThanZero(string paramName, int size)
    {
        if (size <= 0)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} must be greater than 0.");
    }

    public static void NotLessThanMin(string paramName, int size, int minSize)
    {
        if (size < minSize)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} must be equal to or greater than {minSize}.");
    }

    public static void NotEmpty(string paramName, int size)
    {
        if (size == 0)
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} cannot have a length of 0.");
    }
    
    public static void NotNull<T>(string paramName, T value) where T: class
    {
        if (value == null)
            throw new ArgumentNullException(paramName, $"{paramName} cannot be null.");
    }

    public static void NotNullOrEmpty(string paramName, string value)
    {
        if (value == null)
            throw new ArgumentNullException(paramName, $"{paramName} cannot be null.");
        if (value.Length == 0)
            throw new ArgumentOutOfRangeException(paramName, $"{paramName} cannot be empty.");
    }
}