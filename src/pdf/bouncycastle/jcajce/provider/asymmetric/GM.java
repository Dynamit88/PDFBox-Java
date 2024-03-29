package pdf.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import pdf.bouncycastle.asn1.gm.GMObjectIdentifiers;
import pdf.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import pdf.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class GM
{
    private static final String PREFIX = "pdf.bouncycastle.jcajce.provider.asymmetric" + ".ec.";

    private static final Map<String, String> generalSm2Attributes = new HashMap<String, String>();

    static
    {
        generalSm2Attributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        generalSm2Attributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Signature.SM3WITHSM2", PREFIX + "GMSignatureSpi$sm3WithSM2");
            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_sm3, "SM3WITHSM2");

            provider.addAlgorithm("Cipher.SM2", PREFIX + "GMCipherSpi$SM2");
            provider.addAlgorithm("Alg.Alias.Cipher.SM2WITHSM3", "SM2");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sm3, "SM2");
            provider.addAlgorithm("Cipher.SM2WITHBLAKE2B", PREFIX + "GMCipherSpi$SM2withBlake2b");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_blake2b512, "SM2WITHBLAKE2B");
            provider.addAlgorithm("Cipher.SM2WITHBLAKE2S", PREFIX + "GMCipherSpi$SM2withBlake2s");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_blake2s256, "SM2WITHBLAKE2S");
            provider.addAlgorithm("Cipher.SM2WITHWHIRLPOOL", PREFIX + "GMCipherSpi$SM2withWhirlpool");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_whirlpool, "SM2WITHWHIRLPOOL");
            provider.addAlgorithm("Cipher.SM2WITHMD5", PREFIX + "GMCipherSpi$SM2withMD5");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_md5, "SM2WITHMD5");
            provider.addAlgorithm("Cipher.SM2WITHRIPEMD160", PREFIX + "GMCipherSpi$SM2withRMD");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_rmd160, "SM2WITHRIPEMD160");
            provider.addAlgorithm("Cipher.SM2WITHSHA1", PREFIX + "GMCipherSpi$SM2withSha1");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha1, "SM2WITHSHA1");
            provider.addAlgorithm("Cipher.SM2WITHSHA224", PREFIX + "GMCipherSpi$SM2withSha224");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha224, "SM2WITHSHA224");
            provider.addAlgorithm("Cipher.SM2WITHSHA256", PREFIX + "GMCipherSpi$SM2withSha256");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha256, "SM2WITHSHA256");
            provider.addAlgorithm("Cipher.SM2WITHSHA384", PREFIX + "GMCipherSpi$SM2withSha384");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha384, "SM2WITHSHA384");
            provider.addAlgorithm("Cipher.SM2WITHSHA512", PREFIX + "GMCipherSpi$SM2withSha512");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha512, "SM2WITHSHA512");
        }
    }
}
