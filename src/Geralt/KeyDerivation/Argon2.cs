using Geralt.Exceptions;
using System;

/*
    Geralt: A cryptographic library for .NET based on libsodium.
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
    public static class Argon2
    {
        public const int SaltSize = 16;
        private const int _stringOutputLength = 16;
        private const int _defaultOutputLength = 32;
        private const int _minimumArgon2idIterations = 3;
        private const int _minimumArgon2iIterations = 11;
        private const int _iterationsInteractive = 4;
        private const int _iterationsModerate = 6;
        private const int _iterationsSensitive = 8;
        private const int _memorySizeInteractive = 67108864;
        private const int _memorySizeModerate = 134217728;
        private const int _memorySizeSensitive = 536870912;

        /// <summary>The supported Argon2 algorithms.</summary>
        public enum Algorithm
        {
            /// <summary>The Argon2i algorithm. Requires 11+ iterations to be secure.</summary>
            Argon2i = 1,
            /// <summary>The default and recommended algorithm.</summary>
            Argon2id = 2
        }

        /// <summary>Predefined parameter settings.</summary>
        public enum Strength
        {
            /// <summary>For interactive sessions (uses 64 MiB of RAM).</summary>
            Interactive,
            /// <summary>For normal use (uses 128 MiB of RAM).</summary>
            Moderate,
            /// <summary>For highly sensitive data (uses 512 MiB of RAM).</summary>
            Sensitive
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
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int memorySize, int outputLength = _defaultOutputLength, Algorithm algorithm = Algorithm.Argon2id)
        {
            ParameterValidation.Password(password);
            ParameterValidation.Salt(salt, SaltSize);
            ParameterValidation.Iterations(iterations, _minimumArgon2idIterations, _minimumArgon2iIterations, algorithm);
            ParameterValidation.MemorySize(memorySize);
            ParameterValidation.OutputLength(outputLength);
            byte[] key = new byte[outputLength];
            GeraltCore.InitialiseLibsodium();
            int result = LibsodiumLibrary.crypto_pwhash(key, key.Length, password, password.Length, salt, iterations, memorySize, (int)algorithm);
            ResultValidation.PasswordHashingResult(result);
            return key;
        }

        /// <summary>Derives a key of any size from a password and a salt.</summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">A 16 byte salt.</param>
        /// <param name="strength">The strength for computation.</param>
        /// <param name="outputLength">The length of the computed hash.</param>
        /// <param name="algorithm">The Argon2 algorithm. Argon2id is recommended.</param>
        /// <returns>A byte array of the specified output length.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="SaltOutOfRangeException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="OutOfMemoryException"></exception>
        public static byte[] DeriveKey(byte[] password, byte[] salt, Strength strength = Strength.Interactive, int outputLength = _defaultOutputLength, Algorithm algorithm = Algorithm.Argon2id)
        {
            (int iterations, int memorySize) = GetParameters(strength);
            return DeriveKey(password, salt, iterations, memorySize, outputLength, algorithm);
        }

        /// <summary>Computes the hash of a password.</summary>
        /// <param name="password">The password.</param>
        /// <param name="iterations">The number of iterations to perform.</param>
        /// <param name="memorySize">The amount of memory to use (in bytes).</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static byte[] ComputeHash(byte[] password, int iterations, int memorySize)
        {
            ParameterValidation.Password(password);
            ParameterValidation.Iterations(iterations, _minimumArgon2idIterations, _minimumArgon2iIterations, Algorithm.Argon2id);
            ParameterValidation.MemorySize(memorySize);
            GeraltCore.InitialiseLibsodium();
            byte[] hash = new byte[_stringOutputLength];
            GeraltCore.InitialiseLibsodium();
            int result = LibsodiumLibrary.crypto_pwhash_str(hash, password, password.Length, iterations, memorySize);
            ResultValidation.PasswordHashingResult(result);
            return hash;
        }

        /// <summary>Verifies that a hash matches the supplied password.</summary>
        /// <param name="hash">The password hash.</param>
        /// <param name="password">The password.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool VerifyHash(byte[] hash, byte[] password)
        {
            ParameterValidation.Hash(hash);
            ParameterValidation.Password(password);
            GeraltCore.InitialiseLibsodium();
            int result = LibsodiumLibrary.crypto_pwhash_str_verify(hash, password, password.Length);
            return result == 0;
        }

        /// <summary>Checks if a password hash matches the iterations and memory size parameters.</summary>
        /// <param name="hash">The password hash.</param>
        /// <param name="strength">The strength preset.</param>
        /// <returns><c>true</c> if the hash is correct; otherwise, <c>false</c>.</returns>
        public static bool VerifyParameters(byte[] hash, Strength strength = Strength.Interactive)
        {
            (int iterations, int memorySize) = GetParameters(strength);
            return VerifyParameters(hash, iterations, memorySize);
        }

        /// <summary>Checks if a password hash matches the iterations and memory size parameters.</summary>
        /// <param name="hash">The password hash.</param>
        /// <param name="iterations">The number of iterations.</param>
        /// <param name="memorySize">The amount of memory.</param>
        /// <returns><c>true</c> if the hash is correct; otherwise, <c>false</c>.</returns>
        public static bool VerifyParameters(byte[] hash, int iterations, int memorySize)
        {
            ParameterValidation.Password(hash);
            GeraltCore.InitialiseLibsodium();
            int result = LibsodiumLibrary.crypto_pwhash_str_needs_rehash(hash, iterations, memorySize);
            return result == -1 ? throw new InvalidArgonPasswordString() : result == 1;
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
    }
}
