package pdf.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Mac;

import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.cms.CMSException;
import pdf.bouncycastle.cms.KeyTransRecipientId;
import pdf.bouncycastle.cms.RecipientOperator;
import pdf.bouncycastle.jcajce.io.MacOutputStream;
import pdf.bouncycastle.operator.GenericKey;
import pdf.bouncycastle.operator.MacCalculator;
import pdf.bouncycastle.operator.jcajce.JceGenericKey;


/**
 * the KeyTransRecipient class for a recipient who has been sent secret
 * key material encrypted using their public key that needs to be used to
 * derive a key and authenticate a message.
 */
public class JceKTSKeyTransAuthenticatedRecipient
    extends JceKTSKeyTransRecipient
{
    public JceKTSKeyTransAuthenticatedRecipient(PrivateKey recipientKey, KeyTransRecipientId recipientId)
        throws IOException
    {
        super(recipientKey, getPartyVInfoFromRID(recipientId));
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentMacAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        final Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, encryptedContentEncryptionKey);

        final Mac dataMac = contentHelper.createContentMac(secretKey, contentMacAlgorithm);

        return new RecipientOperator(new MacCalculator()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentMacAlgorithm;
            }

            public GenericKey getKey()
            {
                return new JceGenericKey(contentMacAlgorithm, secretKey);
            }

            public OutputStream getOutputStream()
            {
                return new MacOutputStream(dataMac);
            }

            public byte[] getMac()
            {
                return dataMac.doFinal();
            }
        });
    }
}
