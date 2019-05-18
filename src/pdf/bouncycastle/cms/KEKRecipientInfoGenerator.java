package pdf.bouncycastle.cms;

import pdf.bouncycastle.asn1.ASN1OctetString;
import pdf.bouncycastle.asn1.DEROctetString;
import pdf.bouncycastle.asn1.cms.KEKIdentifier;
import pdf.bouncycastle.asn1.cms.KEKRecipientInfo;
import pdf.bouncycastle.asn1.cms.RecipientInfo;
import pdf.bouncycastle.operator.GenericKey;
import pdf.bouncycastle.operator.OperatorException;
import pdf.bouncycastle.operator.SymmetricKeyWrapper;

public abstract class KEKRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    private final KEKIdentifier kekIdentifier;

    protected final SymmetricKeyWrapper wrapper;

    protected KEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, SymmetricKeyWrapper wrapper)
    {
        this.kekIdentifier = kekIdentifier;
        this.wrapper = wrapper;
    }

    public final RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException
    {
        try
        {
            ASN1OctetString encryptedKey = new DEROctetString(wrapper.generateWrappedKey(contentEncryptionKey));

            return new RecipientInfo(new KEKRecipientInfo(kekIdentifier, wrapper.getAlgorithmIdentifier(), encryptedKey));
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception wrapping content key: " + e.getMessage(), e);
        }
    }
}