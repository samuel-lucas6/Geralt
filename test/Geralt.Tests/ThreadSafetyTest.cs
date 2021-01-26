using System;
using System.Linq;
using System.Threading;
using NUnit.Framework;
using Geralt;

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

namespace Tests
{
    class TestWorker
    {
        public Exception Exception;

        public void Random()
        {
            try
            {
                var bytes = GeraltCore.GetRandomBytes(32);

                //this is mostly to make the compiler happier, as otherwise, bytes is never used
                if (bytes.Count() != 32)
                    throw new Exception("GetRandomCountMismatch");
            }
            catch (Exception ex)
            {
                Exception = ex;
            }
        }
    }

    /// <summary>Tests the thread safety</summary>
    [TestFixture]
    class ThreadSafetyTest
    {
        /// <summary>Does CryptoHash.Hash(string) return the expected value?</summary>
        [Test]
        public void ThreadSafetyRandomTest()
        {
            const int CONCURRENCY = 2;
            var workers = new TestWorker[CONCURRENCY];
            var threads = new Thread[CONCURRENCY];

            for (var i = 0; i < CONCURRENCY; i++)
            {
                workers[i] = new TestWorker();
                threads[i] = new Thread(workers[i].Random);
                threads[i].Start();
            }

            for (var i = 0; i < CONCURRENCY; i++)
            {
                threads[i].Join();
            }

            for (var i = 0; i < CONCURRENCY; i++)
            {
                Assert.IsNull(workers[i].Exception);
            }
        }
    }
}
