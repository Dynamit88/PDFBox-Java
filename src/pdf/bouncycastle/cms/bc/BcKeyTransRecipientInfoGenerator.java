package pdf.bouncycastle.cms.bc;

import pdf.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import pdf.bouncycastle.cert.X509CertificateHolder;
import pdf.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import pdf.bouncycastle.operator.bc.BcAsymmetricKeyWrapper;

public abstract class BcKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    public BcKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert, BcAsymmetricKeyWrapper wrapper)
    {
        super(new IssuerAndSerialNumber(recipientCert.toASN1Structure()), wrapper);
    }

    public BcKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, BcAsymmetricKeyWrapper wrapper)
    {
        super(subjectKeyIdentifier, wrapper);
    }
}