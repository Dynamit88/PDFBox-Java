package pdf.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Iterator;

import pdf.bouncycastle.asn1.ASN1EncodableVector;
import pdf.bouncycastle.asn1.ASN1OctetString;
import pdf.bouncycastle.asn1.ASN1Set;
import pdf.bouncycastle.asn1.BEROctetString;
import pdf.bouncycastle.asn1.BERSet;
import pdf.bouncycastle.asn1.DERSet;
import pdf.bouncycastle.asn1.cms.AttributeTable;
import pdf.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import pdf.bouncycastle.asn1.cms.ContentInfo;
import pdf.bouncycastle.asn1.cms.EncryptedContentInfo;
import pdf.bouncycastle.asn1.cms.EnvelopedData;
import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.operator.GenericKey;
import pdf.bouncycastle.operator.OutputEncryptor;

/**
 * General class for generating a CMS enveloped-data message.
 *
 * A simple example of usage.
 *
 * <pre>
 *       CMSTypedData msg     = new CMSProcessableByteArray("Hello World!".getBytes());
 *
 *       CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
 *
 *       edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
 *
 *       CMSEnvelopedData ed = edGen.generate(
 *                                       msg,
 *                                       new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
 *                                              .setProvider("BC").build());
 *
 * </pre>
 */
public class CMSEnvelopedDataGenerator
    extends CMSEnvelopedGenerator
{
    /**
     * base constructor
     */
    public CMSEnvelopedDataGenerator()
    {
    }

    private CMSEnvelopedData doGenerate(
        CMSTypedData content,
        OutputEncryptor contentEncryptor)
        throws CMSException
    {
        if (!oldRecipientInfoGenerators.isEmpty())
        {
            throw new IllegalStateException("can only use addRecipientGenerator() with this method");
        }

        ASN1EncodableVector     recipientInfos = new ASN1EncodableVector();
        AlgorithmIdentifier     encAlgId;
        ASN1OctetString         encContent;

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            OutputStream cOut = contentEncryptor.getOutputStream(bOut);

            content.write(cOut);

            cOut.close();
        }
        catch (IOException e)
        {
            throw new CMSException("");
        }

        byte[] encryptedContent = bOut.toByteArray();

        encAlgId = contentEncryptor.getAlgorithmIdentifier();

        encContent = new BEROctetString(encryptedContent);

        GenericKey encKey = contentEncryptor.getKey();

        for (Iterator it = recipientInfoGenerators.iterator(); it.hasNext();)
        {
            RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

            recipientInfos.add(recipient.generate(encKey));
        }

        EncryptedContentInfo  eci = new EncryptedContentInfo(
                        content.getContentType(),
                        encAlgId,
                        encContent);

        ASN1Set unprotectedAttrSet = null;
        if (unprotectedAttributeGenerator != null)
        {
            AttributeTable attrTable = unprotectedAttributeGenerator.getAttributes(new HashMap());

            unprotectedAttrSet = new BERSet(attrTable.toASN1EncodableVector());
        }

        ContentInfo contentInfo = new ContentInfo(
                CMSObjectIdentifiers.envelopedData,
                new EnvelopedData(originatorInfo, new DERSet(recipientInfos), eci, unprotectedAttrSet));

        return new CMSEnvelopedData(contentInfo);
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     *
     * @param content the content to be encrypted
     * @param contentEncryptor the symmetric key based encryptor to encrypt the content with.
     */
    public CMSEnvelopedData generate(
        CMSTypedData content,
        OutputEncryptor contentEncryptor)
        throws CMSException
    {
        return doGenerate(content, contentEncryptor);
    }
}
