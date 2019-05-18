package pdf.bouncycastle.cert.path;

import pdf.bouncycastle.cert.X509CertificateHolder;
import pdf.bouncycastle.util.Memoable;

public interface CertPathValidation
    extends Memoable
{
    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException;
}
