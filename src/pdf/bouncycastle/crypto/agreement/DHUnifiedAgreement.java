package pdf.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import pdf.bouncycastle.crypto.CipherParameters;
import pdf.bouncycastle.crypto.params.DHUPrivateParameters;
import pdf.bouncycastle.crypto.params.DHUPublicParameters;
import pdf.bouncycastle.util.Arrays;
import pdf.bouncycastle.util.BigIntegers;

/**
 * FFC Unified static/ephemeral agreement as described in NIST SP 800-56A.
 */
public class DHUnifiedAgreement
{
    private DHUPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (DHUPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        DHUPublicParameters pubParams = (DHUPublicParameters)pubKey;

        DHBasicAgreement sAgree = new DHBasicAgreement();
        DHBasicAgreement eAgree = new DHBasicAgreement();

        sAgree.init(privParams.getStaticPrivateKey());

        BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

        eAgree.init(privParams.getEphemeralPrivateKey());

        BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

        return Arrays.concatenate(
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), eComp),
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), sComp));
    }
}
