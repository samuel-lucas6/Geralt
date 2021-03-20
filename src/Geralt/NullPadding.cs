using System;

/*
    Geralt: A cryptographic library for .NET based on libsodium.
    Copyright (c) 2021 Samuel Lucas
    Copyright (c) 2017-2020 tabrath
    Copyright (c) 2013-2017 Adam Caudill & Contributors

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

namespace Geralt
{
    internal static class NullPadding
    {
        internal static byte[] RemoveLeadingNulls(byte[] ciphertext, int tagBytes)
        {
            // Check to see if there are _tagBytes of leading nulls. If so, trim.
            // This is required due to an error in older versions.
            if (ciphertext[0] == 0)
            {
                bool trim = true;
                for (int i = 0; i < tagBytes - 1; i++)
                {
                    if (ciphertext[i] != 0)
                    {
                        trim = false;
                        break;
                    }
                }
                if (trim)
                {
                    byte[] trimmedCiphertext = new byte[ciphertext.Length - tagBytes];
                    Array.Copy(ciphertext, tagBytes, trimmedCiphertext, destinationIndex: 0, trimmedCiphertext.Length);
                    return trimmedCiphertext;
                }
            }
            return ciphertext;
        }

        internal static byte[] RemoveTrailingNulls(byte[] message, long messageLength)
        {
            byte[] trimmedMessage = new byte[message.Length];
            Array.Copy(message, trimmedMessage, (int)messageLength);
            return trimmedMessage;
        }
    }
}
