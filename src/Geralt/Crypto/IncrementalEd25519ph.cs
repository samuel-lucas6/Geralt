using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalEd25519ph : IDisposable
{
    public const int PublicKeySize = Ed25519.PublicKeySize;
    public const int PrivateKeySize = Ed25519.PrivateKeySize;
    public const int SignatureSize = Ed25519.SignatureSize;

    internal const int StateSize = crypto_sign_ed25519ph_STATEBYTES;

    private unsafe void* _state;
    private int _locked;
    private int _finalized;
    private int _disposed;

    public IncrementalEd25519ph()
    {
        Sodium.Initialize();
        Reinitialize();
    }

    public unsafe void Reinitialize()
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot reinitialize from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
            if (_state == null) {
                _state = NativeMemory.Alloc(StateSize);
            }
            int ret = crypto_sign_ed25519ph_init(_state);
            if (ret != 0) { throw new CryptographicException("Error initializing signature scheme state."); }
            _finalized = 0;
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot update from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
            if (_finalized != 0) { throw new InvalidOperationException("Cannot update after finalizing without reinitializing."); }
            int ret = crypto_sign_ed25519ph_update(_state, message, (ulong)message.Length);
            if (ret != 0) { throw new CryptographicException("Error updating signature scheme state."); }
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public unsafe void Finalize(Span<byte> signature, ReadOnlySpan<byte> privateKey)
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot finalize from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
            if (_finalized != 0) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
            Validation.EqualTo($"{nameof(signature)}.{nameof(signature.Length)}", signature.Length, SignatureSize);
            Validation.EqualTo($"{nameof(privateKey)}.{nameof(privateKey.Length)}", privateKey.Length, PrivateKeySize);
            int ret = crypto_sign_ed25519ph_final_create(_state, signature, signatureLength: out _, privateKey);
            if (ret != 0) { throw new CryptographicException("Error finalizing signature."); }
            _finalized = 1;
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public unsafe bool FinalizeAndVerify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot finalize and verify from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalEd25519ph)); }
            if (_finalized != 0) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
            Validation.EqualTo($"{nameof(signature)}.{nameof(signature.Length)}", signature.Length, SignatureSize);
            Validation.EqualTo($"{nameof(publicKey)}.{nameof(publicKey.Length)}", publicKey.Length, PublicKeySize);
            int ret = crypto_sign_ed25519ph_final_verify(_state, signature, publicKey);
            _finalized = 1;
            return ret == 0;
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private unsafe void Dispose(bool disposing)
    {
        // Skip for finalizer because finalizers must not throw exceptions
        if (disposing && Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot dispose when another method is locked.");
        }
        try {
            // Only dispose once
            if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 0) != 0) { return; }
            if (_state != null) {
                SecureMemory.ZeroMemory(new Span<byte>(_state, StateSize));
                NativeMemory.Free(_state);
                _state = null;
            }
        }
        finally {
            if (disposing) {
                Interlocked.Exchange(ref _locked, value: 0);
            }
        }
    }

    ~IncrementalEd25519ph()
    {
        Dispose(false);
    }
}
