package pdf.bouncycastle.cms;

import pdf.bouncycastle.asn1.cms.RecipientInfo;
import pdf.bouncycastle.operator.GenericKey;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}
