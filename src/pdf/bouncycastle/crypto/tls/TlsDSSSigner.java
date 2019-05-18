package pdf.bouncycastle.crypto.tls;

import pdf.bouncycastle.crypto.DSA;
import pdf.bouncycastle.crypto.params.AsymmetricKeyParameter;
import pdf.bouncycastle.crypto.params.DSAPublicKeyParameters;
import pdf.bouncycastle.crypto.signers.DSASigner;
import pdf.bouncycastle.crypto.signers.HMacDSAKCalculator;

public class TlsDSSSigner
    extends TlsDSASigner
{
    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof DSAPublicKeyParameters;
    }

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new DSASigner(new HMacDSAKCalculator(TlsUtils.createHash(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
