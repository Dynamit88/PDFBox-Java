package pdf.bouncycastle.cert.ocsp.jcajce;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import pdf.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import pdf.bouncycastle.cert.ocsp.CertificateID;
import pdf.bouncycastle.cert.ocsp.OCSPException;
import pdf.bouncycastle.operator.DigestCalculator;

public class JcaCertificateID
    extends CertificateID
{
    public JcaCertificateID(DigestCalculator digestCalculator, X509Certificate issuerCert, BigInteger number)
        throws OCSPException, CertificateEncodingException
    {
        super(digestCalculator, new JcaX509CertificateHolder(issuerCert), number);
    }
}
