using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class HChaCha20
{
    public const int OutputSize = crypto_core_hchacha20_OUTPUTBYTES;
    public const int KeySize = crypto_core_hchacha20_KEYBYTES;
    public const int NonceSize = crypto_core_hchacha20_INPUTBYTES;
    public const int PersonalizationSize = crypto_core_hchacha20_CONSTBYTES;

    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> personalization = default)
    {
        Validation.EqualToSize(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, OutputSize);
        Validation.EqualToSize(nameof(inputKeyingMaterial), inputKeyingMaterial.Length, KeySize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        if (personalization.Length != 0) {
            Validation.EqualToSize(nameof(personalization), personalization.Length, PersonalizationSize);
            // https://link.springer.com/article/10.1007/s00145-018-9297-9
            if (ConstantTime.IsAllZeros(personalization)) { throw new FormatException($"{nameof(personalization)} cannot be all-zero."); }
            if (ConstantTime.Equals(personalization[..8], personalization[8..])) { throw new FormatException($"{nameof(personalization)} must have asymmetry."); }
        }
        Sodium.Initialize();
        int ret = crypto_core_hchacha20(outputKeyingMaterial, nonce, inputKeyingMaterial, personalization);
        if (ret != 0) { throw new CryptographicException("Error deriving key."); }
    }
}
