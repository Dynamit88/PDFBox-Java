package pdf.bouncycastle.cert.path.validations;

import pdf.bouncycastle.cert.X509CertificateHolder;

class ValidationUtils
{
    static boolean isSelfIssued(X509CertificateHolder cert)
    {
        return cert.getSubject().equals(cert.getIssuer());
    }
}
