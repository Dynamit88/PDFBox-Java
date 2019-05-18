package pdf.bouncycastle.cert.ocsp.jcajce;

import java.security.PublicKey;

import pdf.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import pdf.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import pdf.bouncycastle.cert.ocsp.OCSPException;
import pdf.bouncycastle.operator.DigestCalculator;

public class JcaBasicOCSPRespBuilder
    extends BasicOCSPRespBuilder
{
    public JcaBasicOCSPRespBuilder(PublicKey key, DigestCalculator digCalc)
        throws OCSPException
    {
        super(SubjectPublicKeyInfo.getInstance(key.getEncoded()), digCalc);
    }
}
