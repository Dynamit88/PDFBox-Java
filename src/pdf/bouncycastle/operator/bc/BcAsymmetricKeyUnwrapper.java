package pdf.bouncycastle.operator.bc;

import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.crypto.AsymmetricBlockCipher;
import pdf.bouncycastle.crypto.InvalidCipherTextException;
import pdf.bouncycastle.crypto.params.AsymmetricKeyParameter;
import pdf.bouncycastle.operator.AsymmetricKeyUnwrapper;
import pdf.bouncycastle.operator.GenericKey;
import pdf.bouncycastle.operator.OperatorException;

public abstract class BcAsymmetricKeyUnwrapper
    extends AsymmetricKeyUnwrapper
{
    private AsymmetricKeyParameter privateKey;

    public BcAsymmetricKeyUnwrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter privateKey)
    {
        super(encAlgId);

        this.privateKey = privateKey;
    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        AsymmetricBlockCipher keyCipher = createAsymmetricUnwrapper(this.getAlgorithmIdentifier().getAlgorithm());

        keyCipher.init(false, privateKey);
        try
        {
            byte[] key = keyCipher.processBlock(encryptedKey, 0, encryptedKey.length);

            if (encryptedKeyAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.des_EDE3_CBC))
            {
                return new GenericKey(encryptedKeyAlgorithm, key);
            }
            else
            {
                return new GenericKey(encryptedKeyAlgorithm, key);
            }
        }
        catch (InvalidCipherTextException e)
        {
            throw new OperatorException("unable to recover secret key: " + e.getMessage(), e);
        }
    }

    protected abstract AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm);
}
