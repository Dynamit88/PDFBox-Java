package pdf.bouncycastle.cert.cmp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import pdf.bouncycastle.asn1.ASN1EncodableVector;
import pdf.bouncycastle.asn1.DERSequence;
import pdf.bouncycastle.asn1.cmp.CertConfirmContent;
import pdf.bouncycastle.asn1.cmp.CertStatus;
import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.cert.X509CertificateHolder;
import pdf.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import pdf.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import pdf.bouncycastle.operator.DigestCalculator;
import pdf.bouncycastle.operator.DigestCalculatorProvider;
import pdf.bouncycastle.operator.OperatorCreationException;

public class CertificateConfirmationContentBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgFinder;
    private List acceptedCerts = new ArrayList();
    private List acceptedReqIds = new ArrayList();

    public CertificateConfirmationContentBuilder()
    {
        this(new DefaultDigestAlgorithmIdentifierFinder());
    }

    public CertificateConfirmationContentBuilder(DigestAlgorithmIdentifierFinder digestAlgFinder)
    {
        this.digestAlgFinder = digestAlgFinder;
    }
    
    public CertificateConfirmationContentBuilder addAcceptedCertificate(X509CertificateHolder certHolder, BigInteger certReqID)
    {
        acceptedCerts.add(certHolder);
        acceptedReqIds.add(certReqID);

        return this;
    }

    public CertificateConfirmationContent build(DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != acceptedCerts.size(); i++)
        {
            X509CertificateHolder certHolder = (X509CertificateHolder)acceptedCerts.get(i);
            BigInteger reqID = (BigInteger)acceptedReqIds.get(i);

            AlgorithmIdentifier digAlg = digestAlgFinder.find(certHolder.toASN1Structure().getSignatureAlgorithm());
            if (digAlg == null)
            {
                throw new CMPException("cannot find algorithm for digest from signature");
            }

            DigestCalculator digester;

            try
            {
                digester = digesterProvider.get(digAlg);
            }
            catch (OperatorCreationException e)
            {
                throw new CMPException("unable to create digest: " + e.getMessage(), e);
            }

            CMPUtil.derEncodeToStream(certHolder.toASN1Structure(), digester.getOutputStream());

            v.add(new CertStatus(digester.getDigest(), reqID));
        }

        return new CertificateConfirmationContent(CertConfirmContent.getInstance(new DERSequence(v)), digestAlgFinder);
    }

}
