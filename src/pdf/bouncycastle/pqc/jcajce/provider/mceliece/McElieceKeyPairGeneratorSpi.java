package pdf.bouncycastle.pqc.jcajce.provider.mceliece;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import pdf.bouncycastle.crypto.AsymmetricCipherKeyPair;
import pdf.bouncycastle.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
import pdf.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
import pdf.bouncycastle.pqc.crypto.mceliece.McElieceParameters;
import pdf.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import pdf.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import pdf.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;

public class McElieceKeyPairGeneratorSpi
    extends KeyPairGenerator
{
    McElieceKeyPairGenerator kpg;

    public McElieceKeyPairGeneratorSpi()
    {
        super("McEliece");
    }
    
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        kpg = new McElieceKeyPairGenerator();
        McElieceKeyGenParameterSpec ecc = (McElieceKeyGenParameterSpec)params;

        McElieceKeyGenerationParameters mccKGParams = new McElieceKeyGenerationParameters(
            random, new McElieceParameters(ecc.getM(), ecc.getT()));
        kpg.init(mccKGParams);
    }

    public void initialize(int keySize, SecureRandom random)
    {
        McElieceKeyGenParameterSpec paramSpec = new McElieceKeyGenParameterSpec();

        // call the initializer with the chosen parameters
        try
        {
            this.initialize(paramSpec, random);
        }
        catch (InvalidAlgorithmParameterException ae)
        {
        }
    }

    public KeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair generateKeyPair = kpg.generateKeyPair();
        McEliecePrivateKeyParameters sk = (McEliecePrivateKeyParameters)generateKeyPair.getPrivate();
        McEliecePublicKeyParameters pk = (McEliecePublicKeyParameters)generateKeyPair.getPublic();

        return new KeyPair(new BCMcEliecePublicKey(pk), new BCMcEliecePrivateKey(sk));
    }

}
