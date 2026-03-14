using System.Numerics;

namespace Geralt;

public static class Validation
{
    public static void EqualTo<T>(string paramName, T value, T required) where T : IBinaryInteger<T>
    {
        if (value != required) {
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must be equal to {required}.");
        }
    }

    public static void Between<T>(string paramName, T value, T min, T max) where T : IBinaryInteger<T>
    {
        if (value <= min || value >= max) {
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must be between {min} and {max} (exclusive).");
        }
    }

    public static void BetweenOrEqualTo<T>(string paramName, T value, T min, T max) where T : IBinaryInteger<T>
    {
        if (value < min || value > max) {
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must be between {min} and {max} (inclusive).");
        }
    }

    public static void GreaterThan<T>(string paramName, T value, T min) where T : IBinaryInteger<T>
    {
        if (value <= min) {
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must be greater than {min}.");
        }
    }

    public static void GreaterThanOrEqualTo<T>(string paramName, T value, T min) where T : IBinaryInteger<T>
    {
        if (value < min) {
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must be greater than or equal to {min}.");
        }
    }

    public static void LessThan<T>(string paramName, T value, T max) where T : IBinaryInteger<T>
    {
        if (value >= max) {
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must be less than {max}.");
        }
    }

    public static void LessThanOrEqualTo<T>(string paramName, T value, T max) where T : IBinaryInteger<T>
    {
        if (value > max) {
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must be less than or equal to {max}.");
        }
    }

    public static void MultipleOf<T>(string paramName, T value, T multipleOf) where T : IBinaryInteger<T>
    {
        if (value <= T.Zero || value % multipleOf != T.Zero) {
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must be a multiple of {multipleOf}.");
        }
    }

    public static void NotEmpty<T>(string paramName, T size) where T : IBinaryInteger<T>
    {
        if (size == T.Zero) {
            throw new ArgumentOutOfRangeException(paramName, size, $"{paramName} must not be empty.");
        }
    }

    public static void NotNull<T>(string paramName, T? value)
    {
        if (value is null) {
            throw new ArgumentNullException(paramName, $"{paramName} must not be null.");
        }
    }

    public static void NotNullOrEmpty<T>(string paramName, IEnumerable<T?> enumerable)
    {
        if (enumerable is null) {
            throw new ArgumentNullException(paramName, $"{paramName} must not be null.");
        }
        if (!enumerable.Any()) {
            throw new ArgumentOutOfRangeException(paramName, $"{paramName} must not be empty.");
        }
    }

    public static void HasNoNullValues<T>(string paramName, IEnumerable<T?> enumerable)
    {
        if (enumerable is null) {
            throw new ArgumentNullException(paramName, $"{paramName} must not be null.");
        }
        if (enumerable.Any(element => element is null)) {
            throw new ArgumentException($"{paramName} must not contain any null values.", paramName);
        }
    }

    public static void HasNoNullOrEmptyValues<T>(string paramName, IEnumerable<T?> enumerable)
    {
        if (enumerable is null) {
            throw new ArgumentNullException(paramName, $"{paramName} must not be null.");
        }
        bool isEmpty = true;
        foreach (var element in enumerable) {
            isEmpty = false;
            if (element is null) {
                throw new ArgumentException($"{paramName} must not contain any null values.", paramName);
            }
            if (typeof(T) == typeof(string) && element is string { Length: 0 }) {
                throw new ArgumentException($"{paramName} must not contain any empty values.", paramName);
            }
        }
        if (isEmpty) {
            throw new ArgumentOutOfRangeException(paramName, $"{paramName} must not be empty.");
        }
    }

    public static void HasNoNullValues<T>(string paramName, IEnumerable<T[]?> jaggedEnumerable)
    {
        if (jaggedEnumerable is null) {
            throw new ArgumentNullException(paramName, $"{paramName} must not be null.");
        }
        foreach (var enumerable in jaggedEnumerable) {
            if (enumerable is null) {
                throw new ArgumentException($"{paramName} must not contain any null collections.", paramName);
            }
            if (enumerable.Any(element => element is null)) {
                throw new ArgumentException($"{paramName} must not contain any null values.", paramName);
            }
        }
    }

    public static void HasNoNullOrEmptyValues<T>(string paramName, IEnumerable<T[]?> jaggedEnumerable)
    {
        if (jaggedEnumerable is null) {
            throw new ArgumentNullException(paramName, $"{paramName} must not be null.");
        }
        bool isEmpty = true;
        foreach (var enumerable in jaggedEnumerable) {
            isEmpty = false;
            if (enumerable is null) {
                throw new ArgumentException($"{paramName} must not contain any null collections.", paramName);
            }
            if (enumerable.Length == 0) {
                throw new ArgumentException($"{paramName} must not contain any empty collections.", paramName);
            }
            foreach (var element in enumerable) {
                if (element is null) {
                    throw new ArgumentException($"{paramName} must not contain any null values.", paramName);
                }
                if (typeof(T) == typeof(string) && element is string { Length: 0 }) {
                    throw new ArgumentException($"{paramName} must not contain any empty values.", paramName);
                }
            }
        }
        if (isEmpty) {
            throw new ArgumentOutOfRangeException(paramName, $"{paramName} must not be empty.");
        }
    }
}
