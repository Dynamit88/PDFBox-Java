package pdf.bouncycastle.eac;

import java.io.OutputStream;

import pdf.bouncycastle.asn1.ASN1Encoding;
import pdf.bouncycastle.asn1.DERApplicationSpecific;
import pdf.bouncycastle.asn1.eac.CVCertificate;
import pdf.bouncycastle.asn1.eac.CertificateBody;
import pdf.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import pdf.bouncycastle.asn1.eac.CertificateHolderReference;
import pdf.bouncycastle.asn1.eac.CertificationAuthorityReference;
import pdf.bouncycastle.asn1.eac.EACTags;
import pdf.bouncycastle.asn1.eac.PackedDate;
import pdf.bouncycastle.asn1.eac.PublicKeyDataObject;
import pdf.bouncycastle.eac.operator.EACSigner;

public class EACCertificateBuilder
{
    private static final byte [] ZeroArray = new byte [] {0};

    private PublicKeyDataObject publicKey;
    private CertificateHolderAuthorization certificateHolderAuthorization;
    private PackedDate certificateEffectiveDate;
    private PackedDate certificateExpirationDate;
    private CertificateHolderReference certificateHolderReference;
    private CertificationAuthorityReference certificationAuthorityReference;

    public EACCertificateBuilder(
        CertificationAuthorityReference certificationAuthorityReference,
        PublicKeyDataObject publicKey,
        CertificateHolderReference certificateHolderReference,
        CertificateHolderAuthorization certificateHolderAuthorization,
        PackedDate certificateEffectiveDate,
        PackedDate certificateExpirationDate)
    {
        this.certificationAuthorityReference = certificationAuthorityReference;
        this.publicKey = publicKey;
        this.certificateHolderReference = certificateHolderReference;
        this.certificateHolderAuthorization = certificateHolderAuthorization;
        this.certificateEffectiveDate = certificateEffectiveDate;
        this.certificateExpirationDate = certificateExpirationDate;
    }

    private CertificateBody buildBody()
    {
        DERApplicationSpecific  certificateProfileIdentifier;

        certificateProfileIdentifier = new DERApplicationSpecific(
                EACTags.INTERCHANGE_PROFILE, ZeroArray);

        CertificateBody body = new CertificateBody(
                certificateProfileIdentifier,
                certificationAuthorityReference,
                publicKey,
                certificateHolderReference,
                certificateHolderAuthorization,
                certificateEffectiveDate,
                certificateExpirationDate);

        return body;
    }

    public EACCertificateHolder build(EACSigner signer)
        throws EACException
    {
        try
        {
            CertificateBody body = buildBody();

            OutputStream vOut = signer.getOutputStream();

            vOut.write(body.getEncoded(ASN1Encoding.DER));

            vOut.close();

            return new EACCertificateHolder(new CVCertificate(body, signer.getSignature()));
        }
        catch (Exception e)
        {
            throw new EACException("unable to process signature: " + e.getMessage(), e);
        }
    }
}
