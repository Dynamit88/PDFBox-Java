package pdf.bouncycastle.cms.bc;

import pdf.bouncycastle.asn1.ASN1OctetString;
import pdf.bouncycastle.asn1.pkcs.PBKDF2Params;
import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.cms.CMSException;
import pdf.bouncycastle.cms.PasswordRecipient;
import pdf.bouncycastle.crypto.InvalidCipherTextException;
import pdf.bouncycastle.crypto.PBEParametersGenerator;
import pdf.bouncycastle.crypto.Wrapper;
import pdf.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import pdf.bouncycastle.crypto.params.KeyParameter;
import pdf.bouncycastle.crypto.params.ParametersWithIV;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using a password.
 */
public abstract class BcPasswordRecipient
    implements PasswordRecipient
{
    private final char[] password;

    private int schemeID = PasswordRecipient.PKCS5_SCHEME2_UTF8;

    BcPasswordRecipient(
        char[] password)
    {
        this.password = password;
    }

    public BcPasswordRecipient setPasswordConversionScheme(int schemeID)
    {
        this.schemeID = schemeID;

        return this;
    }

    protected KeyParameter extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        Wrapper keyEncryptionCipher = EnvelopedDataHelper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

        keyEncryptionCipher.init(false, new ParametersWithIV(new KeyParameter(derivedKey), ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets()));

        try
        {
            return new KeyParameter(keyEncryptionCipher.unwrap(encryptedContentEncryptionKey, 0, encryptedContentEncryptionKey.length));
        }
        catch (InvalidCipherTextException e)
        {
            throw new CMSException("unable to unwrap key: " + e.getMessage(), e);
        }
    }

    public byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
        throws CMSException
    {
        PBKDF2Params params = PBKDF2Params.getInstance(derivationAlgorithm.getParameters());
        byte[] encodedPassword = (schemeID == PasswordRecipient.PKCS5_SCHEME2) ? PBEParametersGenerator.PKCS5PasswordToBytes(password) : PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);

        try
        {
            PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(EnvelopedDataHelper.getPRF(params.getPrf()));

            gen.init(encodedPassword, params.getSalt(), params.getIterationCount().intValue());

            return ((KeyParameter)gen.generateDerivedParameters(keySize)).getKey();
        }
        catch (Exception e)
        {
            throw new CMSException("exception creating derived key: " + e.getMessage(), e);
        }
    }

    public int getPasswordConversionScheme()
    {
        return schemeID;
    }

    public char[] getPassword()
    {
        return password;
    }
}
