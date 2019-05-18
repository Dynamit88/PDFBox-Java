package pdf.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import pdf.bouncycastle.crypto.AsymmetricCipherKeyPair;
import pdf.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import pdf.bouncycastle.crypto.KeyGenerationParameters;
import pdf.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import pdf.bouncycastle.crypto.params.Ed448PublicKeyParameters;

public class Ed448KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(random);
        Ed448PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
