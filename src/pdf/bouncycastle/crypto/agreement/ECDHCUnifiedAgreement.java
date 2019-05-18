package pdf.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import pdf.bouncycastle.crypto.CipherParameters;
import pdf.bouncycastle.crypto.params.ECDHUPrivateParameters;
import pdf.bouncycastle.crypto.params.ECDHUPublicParameters;
import pdf.bouncycastle.util.Arrays;
import pdf.bouncycastle.util.BigIntegers;

/**
 * EC Unified static/ephemeral agreement as described in NIST SP 800-56A using EC co-factor Diffie-Hellman.
 */
public class ECDHCUnifiedAgreement
{
    private ECDHUPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (ECDHUPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        ECDHUPublicParameters pubParams = (ECDHUPublicParameters)pubKey;

        ECDHCBasicAgreement sAgree = new ECDHCBasicAgreement();
        ECDHCBasicAgreement eAgree = new ECDHCBasicAgreement();

        sAgree.init(privParams.getStaticPrivateKey());

        BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

        eAgree.init(privParams.getEphemeralPrivateKey());

        BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

        return Arrays.concatenate(
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), eComp),
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), sComp));
    }
}
