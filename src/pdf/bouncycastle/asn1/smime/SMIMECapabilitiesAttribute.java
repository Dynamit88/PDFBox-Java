package pdf.bouncycastle.asn1.smime;

import pdf.bouncycastle.asn1.DERSequence;
import pdf.bouncycastle.asn1.DERSet;
import pdf.bouncycastle.asn1.cms.Attribute;

public class SMIMECapabilitiesAttribute
    extends Attribute
{
    public SMIMECapabilitiesAttribute(
        SMIMECapabilityVector capabilities)
    {
        super(SMIMEAttributes.smimeCapabilities,
                new DERSet(new DERSequence(capabilities.toASN1EncodableVector())));
    }
}
