using System;
using System.Text;
using Geralt.Exceptions;

/*
    Geralt: libsodium for .NET - A fast, secure, and modern cryptographic library.
    Copyright (c) 2021 Samuel Lucas
    Copyright (c) 2017-2020 tabrath
    Copyright (c) 2013-2017 Adam Caudill & Contributors

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without strengthation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT strengthED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

namespace Geralt
{

    /// <summary>Password hashing using Argon2.</summary>
    /// <remarks>See here for more information: https://doc.libsodium.org/password_hashing/default_phf </remarks>
    public static class Argon2
    {
        private const int _hashStringBytes = 128;
        private const int _defaultOutputLength = 32;
        private const int _saltBytes = 16;
        private const int _minimumIterations = 3;
        private const int _iterationsInteractive = 4;
        private const int _iterationsModerate = 6;
        private const int _iterationsSensitive = 8;
        private const int _memorySizeInteractive = 67108864;
        private const int _memorySizeModerate = 134217728;
        private const int _memorySizeSensitive = 536870912;

        /// <summary>Represents the available Argon2 algorithms.</summary>
        public enum Algorithm
        {
            /// <summary>The Argon2i algorithm. Requires 10+ iterations to be secure.</summary>
            Argon2i = 1,
            /// <summary>The default and recommended algorithm.</summary>
            Argon2id = 2
        }

        /// <summary>Represents predefined and useful parameter strengths.</summary>
        public enum Strength
        {
            /// <summary>For interactive sessions (uses 64 MiB of RAM)</summary>
            Interactive,
            /// <summary>For normal use (uses 128 MiB of RAM).</summary>
            Moderate,
            /// <summary>For highly sensitive data (uses 512 MiB of RAM).</summary>
            Sensitive
        }

        /// <summary>Generates a random 16 byte salt.</summary>
        /// <returns>A byte array with 16 random bytes.</returns>
        public static byte[] GenerateSalt()
        {
            return SecureRandom.GetBytes(_saltBytes);
        }

        /// <summary>Derives a key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">A 16 byte salt.</param>
        /// <param name="iterations">The number of iterations to perform.</param>
        /// <param name="memorySize">The amount of memory to use (in bytes).</param>
        /// <param name="outputLength">The length of the computed hash.</param>
        /// <param name="algorithm">The Argon2 algorithm. Argon2id is recommended.</param>
        /// <returns>A byte array of the specified output length.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] Hash(byte[] password, byte[] salt, int iterations, int memorySize, int outputLength = _defaultOutputLength, Algorithm algorithm = Algorithm.Argon2id)
        {
            ParameterValidation.Password(password);
            ParameterValidation.Salt(salt, _saltBytes);
            ValidateIterations(iterations);
            ValidateMemorySize(memorySize);
            ValidateOutputLength(outputLength);
            byte[] hash = new byte[outputLength];
            GeraltCore.InitialiseLibsodium();
            int result = LibsodiumLibrary.crypto_pwhash(hash, hash.Length, password, password.Length, salt, iterations, memorySize, (int)algorithm);
            ParameterValidation.PasswordHashingResult(result);
            return hash;
        }

        /// <summary>Derives a key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">A 16 character salt.</param>
        /// <param name="strength">The strength for computation.</param>
        /// <param name="outputLength">The length of the computed hash.</param>
        /// <param name="algorithm">The Argon2 algorithm. Argon2id is recommended.</param>
        /// <returns>A byte array of the specified output length.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] Hash(string password, string salt, Strength strength = Strength.Interactive, int outputLength = _defaultOutputLength, Algorithm algorithm = Algorithm.Argon2id)
        {
            return Hash(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), strength, outputLength, algorithm);
        }

        /// <summary>Derives a key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">A 16 byte salt.</param>
        /// <param name="strength">The strength for computation.</param>
        /// <param name="outputLength">The length of the computed hash.</param>
        /// <param name="algorithm">The Argon2 algorithm. Argon2id is recommended.</param>
        /// <returns>A byte array of the specified output length.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] Hash(byte[] password, byte[] salt, Strength strength = Strength.Interactive, int outputLength = _defaultOutputLength, Algorithm algorithm = Algorithm.Argon2id)
        {
            (int iterations, int memorySize) = GetParameters(strength);
            return Hash(password, salt, iterations, memorySize, outputLength, algorithm);
        }

        /// <summary>Derives a key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">A 16 byte salt.</param>
        /// <param name="iterations">The number of iterations to perform.</param>
        /// <param name="memorySize">The amount of memory to use (in bytes).</param>
        /// <param name="outputLength">The length of the computed hash.</param>
        /// <returns>A byte array of the specified output length.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] Hash(string password, string salt, int iterations, int memorySize, int outputLength = _defaultOutputLength)
        {
            return Hash(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), iterations, memorySize, outputLength);
        }

        /// <summary>Returns the hash in a string format, which includes the generated salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="strength">The strength for computation.</param>
        /// <returns>A zero-terminated ASCII encoded string of the computed hash.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static string Hash(string password, Strength strength = Strength.Interactive)
        {
            (int iterations, int memorySize) = GetParameters(strength);
            return Hash(password, iterations, memorySize);
        }

        /// <summary>Returns the hash in a string format, which includes the generated salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="iterations">The number of iterations to perform.</param>
        /// <param name="memorySize">The amount of memory to use (in bytes).</param>
        /// <returns>A zero-terminated ASCII encoded string of the computed hash.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static string Hash(string password, int iterations, int memorySize)
        {
            ParameterValidation.Password(password);
            ValidateIterations(iterations);
            ValidateMemorySize(memorySize);
            byte[] hash = new byte[_hashStringBytes];
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            GeraltCore.InitialiseLibsodium();
            int result = LibsodiumLibrary.crypto_pwhash_str(hash, passwordBytes, passwordBytes.Length, iterations, memorySize);
            ParameterValidation.PasswordHashingResult(result);
            return Utilities.UnsafeAsciiBytesToString(hash);
        }

        /// <summary>Verifies that a string hash matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool Verify(string hash, string password)
        {
            return Verify(Encoding.UTF8.GetBytes(hash), Encoding.UTF8.GetBytes(password));
        }

        /// <summary>Verifies that a hash matches the supplied password.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> on success; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool Verify(byte[] hash, byte[] password)
        {
            ParameterValidation.Hash(hash);
            ParameterValidation.Password(password);
            GeraltCore.InitialiseLibsodium();
            int result = LibsodiumLibrary.crypto_pwhash_str_verify(hash, password, password.Length);
            return result == 0;
        }

        /// <summary>Checks if a password hash matches the iterations and memory size parameters.</summary>
        /// <param name="hash">The password hash to check.</param>
        /// <param name="strength">The strength preset used for the hash.</param>
        /// <returns><c>true</c> if the hash is correct; otherwise, <c>false</c>.</returns>
        public static bool DoesPasswordNeedRehash(byte[] password, Strength strength = Strength.Interactive)
        {
            (int opsLimit, int memLimit) = GetParameters(strength);
            return DoesPasswordNeedRehash(password, opsLimit, memLimit);
        }

        /// <summary>Checks if a password hash matches the iterations and memory size parameters.</summary>
        /// <param name="hash">The password hash to check.</param>
        /// <param name="strength">The strength preset used for the hash.</param>
        /// <returns><c>true</c> if the hash is correct; otherwise, <c>false</c>.</returns>
        public static bool DoesPasswordNeedRehash(string password, Strength strength = Strength.Interactive)
        {
            return DoesPasswordNeedRehash(Encoding.UTF8.GetBytes(password), strength);
        }

        /// <summary>Checks if a password hash matches the iterations and memory size parameters.</summary>
        /// <param name="hash">The password hash to check.</param>
        /// <param name="iterations">The number of iterations used for the hash.</param>
        /// <param name="memorySize">The amount of memory (in bytes) used for the hash.</param>
        /// <returns><c>true</c> if the hash is correct; otherwise, <c>false</c>.</returns>
        public static bool DoesPasswordNeedRehash(string password, int iterations, int memorySize)
        {
            return DoesPasswordNeedRehash(Encoding.UTF8.GetBytes(password), iterations, memorySize);
        }

        /// <summary>Checks if a password hash matches the iterations and memory size parameters.</summary>
        /// <param name="hash">The password hash to check.</param>
        /// <param name="iterations">The number of iterations used for the hash.</param>
        /// <param name="memorySize">The amount of memory (in bytes) used for the hash.</param>
        /// <returns><c>true</c> if the hash is correct; otherwise, <c>false</c>.</returns>
        public static bool DoesPasswordNeedRehash(byte[] hash, int iterations, int memorySize)
        {
            ParameterValidation.Password(hash);
            GeraltCore.InitialiseLibsodium();
            int result = LibsodiumLibrary.crypto_pwhash_str_needs_rehash(hash, iterations, memorySize);
            if (result == -1)
            {
                throw new InvalidArgonPasswordString();
            }
            return result == 1;
        }

        private static (int iterations, int memorySize) GetParameters(Strength strength = Strength.Interactive)
        {
            return strength switch
            {
                Strength.Interactive => (_iterationsInteractive, _memorySizeInteractive),
                Strength.Moderate => (_iterationsModerate, _memorySizeModerate),
                Strength.Sensitive => (_iterationsSensitive, _memorySizeSensitive),
                _ => (_iterationsInteractive, _memorySizeInteractive),
            };
        }

        private static void ValidateIterations(int iterations)
        {
            if (iterations < _minimumIterations)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), $"Iterations must be at least {_minimumIterations}.");
            }
        }

        private static void ValidateMemorySize(int memorySize)
        {
            if (memorySize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(memorySize), "Memory size cannot be zero or negative.");
            }
        }

        private static void ValidateOutputLength(int outputLength)
        {
            if (outputLength <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length cannot be zero or negative.");
            }
        }
    }
}
