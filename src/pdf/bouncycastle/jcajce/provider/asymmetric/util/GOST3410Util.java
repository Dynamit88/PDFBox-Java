package pdf.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import pdf.bouncycastle.crypto.params.AsymmetricKeyParameter;
import pdf.bouncycastle.crypto.params.GOST3410Parameters;
import pdf.bouncycastle.crypto.params.GOST3410PrivateKeyParameters;
import pdf.bouncycastle.crypto.params.GOST3410PublicKeyParameters;
import pdf.bouncycastle.jce.interfaces.GOST3410PrivateKey;
import pdf.bouncycastle.jce.interfaces.GOST3410PublicKey;
import pdf.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

/**
 * utility class for converting jce/jca GOST3410-94 objects
 * objects into their pdf.bouncycastle.crypto counterparts.
 */
public class GOST3410Util
{
    static public AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof GOST3410PublicKey)
        {
            GOST3410PublicKey          k = (GOST3410PublicKey)key;
            GOST3410PublicKeyParameterSetSpec p = k.getParameters().getPublicKeyParameters();
            
            return new GOST3410PublicKeyParameters(k.getY(),
                new GOST3410Parameters(p.getP(), p.getQ(), p.getA()));
        }

        throw new InvalidKeyException("can't identify GOST3410 public key: " + key.getClass().getName());
    }

    static public AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        if (key instanceof GOST3410PrivateKey)
        {
            GOST3410PrivateKey         k = (GOST3410PrivateKey)key;
            GOST3410PublicKeyParameterSetSpec p = k.getParameters().getPublicKeyParameters();
            
            return new GOST3410PrivateKeyParameters(k.getX(),
                new GOST3410Parameters(p.getP(), p.getQ(), p.getA()));
        }

        throw new InvalidKeyException("can't identify GOST3410 private key.");
    }
}
