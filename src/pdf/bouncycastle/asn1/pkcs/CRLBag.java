package pdf.bouncycastle.asn1.pkcs;

import pdf.bouncycastle.asn1.ASN1Encodable;
import pdf.bouncycastle.asn1.ASN1EncodableVector;
import pdf.bouncycastle.asn1.ASN1Object;
import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.ASN1Primitive;
import pdf.bouncycastle.asn1.ASN1Sequence;
import pdf.bouncycastle.asn1.ASN1TaggedObject;
import pdf.bouncycastle.asn1.DERSequence;
import pdf.bouncycastle.asn1.DERTaggedObject;

/**
 * CRL Bag for PKCS#12
 */
public class CRLBag
    extends ASN1Object
{
    private ASN1ObjectIdentifier crlId;
    private ASN1Encodable crlValue;

    private CRLBag(
        ASN1Sequence seq)
    {
        this.crlId = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        this.crlValue = ((ASN1TaggedObject)seq.getObjectAt(1)).getObject();
    }

    public static CRLBag getInstance(Object o)
    {
        if (o instanceof CRLBag)
        {
            return (CRLBag)o;
        }
        else if (o != null)
        {
            return new CRLBag(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CRLBag(
        ASN1ObjectIdentifier crlId,
        ASN1Encodable crlValue)
    {
        this.crlId = crlId;
        this.crlValue = crlValue;
    }

    public ASN1ObjectIdentifier getCrlId()
    {
        return crlId;
    }

    public ASN1Encodable getCrlValue()
    {
        return crlValue;
    }

    /**
     * <pre>
     * CRLBag ::= SEQUENCE {
     * crlId  BAG-TYPE.&amp;id ({CRLTypes}),
     * crlValue  [0] EXPLICIT BAG-TYPE.&amp;Type ({CRLTypes}{&#64;crlId})
     * }
     *
     * x509CRL BAG-TYPE ::= {OCTET STRING IDENTIFIED BY {certTypes 1}
     * -- DER-encoded X.509 CRL stored in OCTET STRING
	 *
     * CRLTypes BAG-TYPE ::= {
     * x509CRL,
     * ... -- For future extensions
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(crlId);
        v.add(new DERTaggedObject(0, crlValue));

        return new DERSequence(v);
    }
}
