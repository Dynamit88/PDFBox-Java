package pdf.bouncycastle.cert.crmf.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.cert.crmf.CRMFException;
import pdf.bouncycastle.crypto.CipherKeyGenerator;
import pdf.bouncycastle.crypto.CryptoServicesRegistrar;
import pdf.bouncycastle.crypto.params.KeyParameter;
import pdf.bouncycastle.crypto.util.CipherFactory;
import pdf.bouncycastle.operator.GenericKey;
import pdf.bouncycastle.operator.OutputEncryptor;

/**
 * Lightweight CRMFOutputEncryptor builder.
 */
public class BcCRMFEncryptorBuilder
{
    private final ASN1ObjectIdentifier encryptionOID;
    private final int                  keySize;

    private CRMFHelper helper = new CRMFHelper();
    private SecureRandom random;

    public BcCRMFEncryptorBuilder(ASN1ObjectIdentifier encryptionOID)
    {
        this(encryptionOID, -1);
    }

    public BcCRMFEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
    {
        this.encryptionOID = encryptionOID;
        this.keySize = keySize;
    }

    public BcCRMFEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public OutputEncryptor build()
        throws CRMFException
    {
        return new CRMFOutputEncryptor(encryptionOID, keySize, random);
    }

    private class CRMFOutputEncryptor
        implements OutputEncryptor
    {
        private KeyParameter encKey;
        private AlgorithmIdentifier algorithmIdentifier;
        private Object cipher;

        CRMFOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
            throws CRMFException
        {
            if (random == null)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }

            CipherKeyGenerator keyGen = helper.createKeyGenerator(encryptionOID, random);

            encKey = new KeyParameter(keyGen.generateKey());
            algorithmIdentifier = helper.generateEncryptionAlgID(encryptionOID, encKey, random);
            cipher = helper.createContentCipher(true, encKey, algorithmIdentifier);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut)
        {
            return CipherFactory.createOutputStream(dOut, cipher);
        }

        public GenericKey getKey()
        {
            return new GenericKey(algorithmIdentifier, encKey.getKey());
        }
    }
}
