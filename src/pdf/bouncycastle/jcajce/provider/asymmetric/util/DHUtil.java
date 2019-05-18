package pdf.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import pdf.bouncycastle.crypto.params.AsymmetricKeyParameter;
import pdf.bouncycastle.crypto.params.DHParameters;
import pdf.bouncycastle.crypto.params.DHPrivateKeyParameters;
import pdf.bouncycastle.crypto.params.DHPublicKeyParameters;
import pdf.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey;

/**
 * utility class for converting jce/jca DH objects
 * objects into their pdf.bouncycastle.crypto counterparts.
 */
public class DHUtil
{
    static public AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof BCDHPublicKey)
        {
            return ((BCDHPublicKey)key).engineGetKeyParameters();
        }
        if (key instanceof DHPublicKey)
        {
            DHPublicKey    k = (DHPublicKey)key;

            return new DHPublicKeyParameters(k.getY(),
                new DHParameters(k.getParams().getP(), k.getParams().getG(), null, k.getParams().getL()));
        }

        throw new InvalidKeyException("can't identify DH public key.");
    }

    static public AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        if (key instanceof DHPrivateKey)
        {
            DHPrivateKey    k = (DHPrivateKey)key;

            return new DHPrivateKeyParameters(k.getX(),
                new DHParameters(k.getParams().getP(), k.getParams().getG(), null, k.getParams().getL()));
        }
                        
        throw new InvalidKeyException("can't identify DH private key.");
    }
}
