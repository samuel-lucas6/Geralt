using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class HChaCha20
{
    public const int OutputSize = crypto_core_hchacha20_OUTPUTBYTES;
    public const int KeySize = crypto_core_hchacha20_KEYBYTES;
    public const int NonceSize = crypto_core_hchacha20_INPUTBYTES;
    public const int PersonalSize = crypto_core_hchacha20_CONSTBYTES;
    
    public static unsafe void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> personalisation = default)
    {
        Validation.EqualToSize(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, OutputSize);
        Validation.EqualToSize(nameof(inputKeyingMaterial), inputKeyingMaterial.Length, KeySize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        if (personalisation != default) { Validation.EqualToSize(nameof(personalisation), personalisation.Length, PersonalSize); }
        Sodium.Initialize();
        fixed (byte* okm = outputKeyingMaterial, ikm = inputKeyingMaterial, n = nonce, p = personalisation)
        {
            int ret = crypto_core_hchacha20(okm, n, ikm, p);
            if (ret != 0) { throw new CryptographicException("Error deriving key."); }
        }
    }
}