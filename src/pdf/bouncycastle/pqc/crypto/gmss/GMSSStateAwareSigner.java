package pdf.bouncycastle.pqc.crypto.gmss;

import pdf.bouncycastle.crypto.CipherParameters;
import pdf.bouncycastle.crypto.Digest;
import pdf.bouncycastle.crypto.params.AsymmetricKeyParameter;
import pdf.bouncycastle.crypto.params.ParametersWithRandom;
import pdf.bouncycastle.pqc.crypto.StateAwareMessageSigner;
import pdf.bouncycastle.util.Memoable;

/**
 * This class implements the GMSS signature scheme, but allows multiple signatures to be generated.
 * <p>
 *     Note:  getUpdatedPrivateKey() needs to be called to fetch the current value of the usable private key.
 * </p>
 */
public class GMSSStateAwareSigner
    implements StateAwareMessageSigner
{
    private final GMSSSigner gmssSigner;

    private GMSSPrivateKeyParameters key;

    public GMSSStateAwareSigner(final Digest digest)
    {
        if (!(digest instanceof Memoable))
        {
            throw new IllegalArgumentException("digest must implement Memoable");
        }

        final Memoable dig = ((Memoable)digest).copy();
        gmssSigner = new GMSSSigner(new GMSSDigestProvider()
        {
            public Digest get()
            {
                return (Digest)dig.copy();
            }
        });
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                this.key = (GMSSPrivateKeyParameters)rParam.getParameters();
            }
            else
            {
                this.key = (GMSSPrivateKeyParameters)param;
            }
        }

        gmssSigner.init(forSigning, param);
    }

    public byte[] generateSignature(byte[] message)
    {
        if (key == null)
        {
            throw new IllegalStateException("signing key no longer usable");
        }
        
        byte[] sig = gmssSigner.generateSignature(message);

        key = key.nextKey();

        return sig;
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return gmssSigner.verifySignature(message, signature);
    }

    public AsymmetricKeyParameter getUpdatedPrivateKey()
    {
        AsymmetricKeyParameter k = key;

        key = null;

        return k;
    }
}