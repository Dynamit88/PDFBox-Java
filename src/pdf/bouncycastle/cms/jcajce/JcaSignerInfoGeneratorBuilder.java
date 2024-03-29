package pdf.bouncycastle.cms.jcajce;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import pdf.bouncycastle.cert.X509CertificateHolder;
import pdf.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import pdf.bouncycastle.cms.CMSAttributeTableGenerator;
import pdf.bouncycastle.cms.CMSSignatureEncryptionAlgorithmFinder;
import pdf.bouncycastle.cms.DefaultCMSSignatureEncryptionAlgorithmFinder;
import pdf.bouncycastle.cms.SignerInfoGenerator;
import pdf.bouncycastle.cms.SignerInfoGeneratorBuilder;
import pdf.bouncycastle.operator.ContentSigner;
import pdf.bouncycastle.operator.DigestCalculatorProvider;
import pdf.bouncycastle.operator.OperatorCreationException;

public class JcaSignerInfoGeneratorBuilder
{
    private SignerInfoGeneratorBuilder builder;

    /**
     *  Base constructor.
     *
     * @param digestProvider  a provider of digest calculators for the algorithms required in the signature and attribute calculations.
     */
    public JcaSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider)
    {
        this(digestProvider, new DefaultCMSSignatureEncryptionAlgorithmFinder());
    }

    /**
     * Base constructor with a particular finder for signature algorithms.
     *
     * @param digestProvider a provider of digest calculators for the algorithms required in the signature and attribute calculations.
     * @param sigEncAlgFinder finder for algorithm IDs to store for the signature encryption/signature algorithm field.
     */
    public JcaSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider, CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder)
    {
        builder = new SignerInfoGeneratorBuilder(digestProvider, sigEncAlgFinder);
    }

    /**
     * If the passed in flag is true, the signer signature will be based on the data, not
     * a collection of signed attributes, and no signed attributes will be included.
     *
     * @return the builder object
     */
    public JcaSignerInfoGeneratorBuilder setDirectSignature(boolean hasNoSignedAttributes)
    {
        builder.setDirectSignature(hasNoSignedAttributes);

        return this;
    }

    public JcaSignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
    {
        builder.setSignedAttributeGenerator(signedGen);

        return this;
    }

    public JcaSignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
    {
        builder.setUnsignedAttributeGenerator(unsignedGen);

        return this;
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, X509CertificateHolder certHolder)
        throws OperatorCreationException
    {
        return builder.build(contentSigner, certHolder);
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, byte[] keyIdentifier)
        throws OperatorCreationException
    {
        return builder.build(contentSigner, keyIdentifier);
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, X509Certificate certificate)
        throws OperatorCreationException, CertificateEncodingException
    {
        return this.build(contentSigner, new JcaX509CertificateHolder(certificate));
    }
}
