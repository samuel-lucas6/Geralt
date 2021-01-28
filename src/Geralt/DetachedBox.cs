/*
    Geralt: libsodium for .NET - A fast, secure, and modern cryptographic library.
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
    /// <summary>A ciphertext/message authentication code pair.</summary>
    public class DetachedBox
    {
        /// <summary>Initializes a new instance of the <see cref="DetachedBox"/> class.</summary>
        public DetachedBox()
        {
            // Do nothing
        }

        /// <summary>Gets or sets the ciphertext.</summary>
        public byte[] Ciphertext { get; set; }

        /// <summary>Gets or sets the message authentication code.</summary>
        public byte[] Tag { get; set; }

        /// <summary>Initializes a new instance of the <see cref="DetachedBox"/> class.</summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <param name="tag">The 16 byte message authentication code.</param>
        public DetachedBox(byte[] ciphertext, byte[] tag)
        {
            Ciphertext = ciphertext;
            Tag = tag;
        }
    }
}
