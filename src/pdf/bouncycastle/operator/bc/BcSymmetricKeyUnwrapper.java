package pdf.bouncycastle.operator.bc;

import java.security.SecureRandom;

import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.crypto.InvalidCipherTextException;
import pdf.bouncycastle.crypto.Wrapper;
import pdf.bouncycastle.crypto.params.KeyParameter;
import pdf.bouncycastle.operator.GenericKey;
import pdf.bouncycastle.operator.OperatorException;
import pdf.bouncycastle.operator.SymmetricKeyUnwrapper;

public class BcSymmetricKeyUnwrapper
    extends SymmetricKeyUnwrapper
{
    private SecureRandom random;
    private Wrapper wrapper;
    private KeyParameter wrappingKey;

    public BcSymmetricKeyUnwrapper(AlgorithmIdentifier wrappingAlgorithm, Wrapper wrapper, KeyParameter wrappingKey)
    {
        super(wrappingAlgorithm);

        this.wrapper = wrapper;
        this.wrappingKey = wrappingKey;
    }

    public BcSymmetricKeyUnwrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        wrapper.init(false, wrappingKey);

        try
        {
            return new GenericKey(encryptedKeyAlgorithm, wrapper.unwrap(encryptedKey, 0, encryptedKey.length));
        }
        catch (InvalidCipherTextException e)
        {
            throw new OperatorException("unable to unwrap key: " + e.getMessage(), e);
        }
    }
}
