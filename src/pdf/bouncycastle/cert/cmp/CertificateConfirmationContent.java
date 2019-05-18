package pdf.bouncycastle.cert.cmp;

import pdf.bouncycastle.asn1.cmp.CertConfirmContent;
import pdf.bouncycastle.asn1.cmp.CertStatus;
import pdf.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import pdf.bouncycastle.operator.DigestAlgorithmIdentifierFinder;

public class CertificateConfirmationContent
{
    private DigestAlgorithmIdentifierFinder digestAlgFinder;
    private CertConfirmContent content;

    public CertificateConfirmationContent(CertConfirmContent content)
    {
        this(content, new DefaultDigestAlgorithmIdentifierFinder());
    }

    public CertificateConfirmationContent(CertConfirmContent content, DigestAlgorithmIdentifierFinder digestAlgFinder)
    {
        this.digestAlgFinder = digestAlgFinder;
        this.content = content;
    }

    public CertConfirmContent toASN1Structure()
    {
        return content;
    }

    public CertificateStatus[] getStatusMessages()
    {
        CertStatus[] statusArray = content.toCertStatusArray();
        CertificateStatus[] ret = new CertificateStatus[statusArray.length];

        for (int i = 0; i != ret.length; i++)
        {
            ret[i] = new CertificateStatus(digestAlgFinder, statusArray[i]);
        }

        return ret;
    }
}
