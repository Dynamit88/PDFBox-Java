package pdf.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import pdf.bouncycastle.crypto.AsymmetricCipherKeyPair;
import pdf.bouncycastle.crypto.CryptoServicesRegistrar;
import pdf.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import pdf.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import pdf.bouncycastle.crypto.params.RSAKeyParameters;
import pdf.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import pdf.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    public KeyPairGeneratorSpi(
        String algorithmName)
    {
        super(algorithmName);
    }

    final static BigInteger defaultPublicExponent = BigInteger.valueOf(0x10001);

    RSAKeyGenerationParameters param;
    RSAKeyPairGenerator engine;

    public KeyPairGeneratorSpi()
    {
        super("RSA");

        engine = new RSAKeyPairGenerator();
        param = new RSAKeyGenerationParameters(defaultPublicExponent,
            CryptoServicesRegistrar.getSecureRandom(), 2048, PrimeCertaintyCalculator.getDefaultCertainty(2048));
        engine.init(param);
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        param = new RSAKeyGenerationParameters(defaultPublicExponent,
            random, strength, PrimeCertaintyCalculator.getDefaultCertainty(strength));

        engine.init(param);
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof RSAKeyGenParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a RSAKeyGenParameterSpec");
        }
        RSAKeyGenParameterSpec rsaParams = (RSAKeyGenParameterSpec)params;

        param = new RSAKeyGenerationParameters(
            rsaParams.getPublicExponent(),
            random, rsaParams.getKeysize(), PrimeCertaintyCalculator.getDefaultCertainty(2048));

        engine.init(param);
    }

    public KeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        RSAKeyParameters pub = (RSAKeyParameters)pair.getPublic();
        RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)pair.getPrivate();

        return new KeyPair(new BCRSAPublicKey(pub),
            new BCRSAPrivateCrtKey(priv));
    }
}
