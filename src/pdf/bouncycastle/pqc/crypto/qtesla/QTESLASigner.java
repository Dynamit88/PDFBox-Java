package pdf.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;

import pdf.bouncycastle.crypto.CipherParameters;
import pdf.bouncycastle.crypto.CryptoServicesRegistrar;
import pdf.bouncycastle.crypto.params.ParametersWithRandom;
import pdf.bouncycastle.pqc.crypto.MessageSigner;

/**
 * Signer for the qTESLA algorithm (https://qtesla.org/)
 */
public class QTESLASigner
    implements MessageSigner
{
    /**
     * The Public Key of the Identity Whose Signature Will be Generated
     */
    private QTESLAPublicKeyParameters publicKey;

    /**
     * The Private Key of the Identity Whose Signature Will be Generated
     */
    private QTESLAPrivateKeyParameters privateKey;

    /**
     * The Source of Randomness for private key operations
     */
    private SecureRandom secureRandom;

    public QTESLASigner()
    {
    }

    /**
     * Initialise the signer.
     *
     * @param forSigning true if we are generating a signature, false
     *                   otherwise.
     * @param param      ParametersWithRandom containing a private key for signature generation, public key otherwise.
     */
    public void init(boolean forSigning, CipherParameters param)
    {
         if (forSigning)
         {
             if (param instanceof ParametersWithRandom)
             {
                 this.secureRandom = ((ParametersWithRandom)param).getRandom();
                 privateKey = (QTESLAPrivateKeyParameters)((ParametersWithRandom)param).getParameters();
             }
             else
             {
                 this.secureRandom = CryptoServicesRegistrar.getSecureRandom();
                 privateKey = (QTESLAPrivateKeyParameters)param;
             }
             publicKey = null;
             QTESLASecurityCategory.validate(privateKey.getSecurityCategory());
         }
         else
         {
             privateKey = null;
             publicKey = (QTESLAPublicKeyParameters)param;
             QTESLASecurityCategory.validate(publicKey.getSecurityCategory());
         }
    }

    /**
     * Generate a signature directly for the passed in message.
     *
     * @param message the message to be signed.
     * @return the signature generated.
     */
    public byte[] generateSignature(byte[] message)
    {
        byte[] sig = new byte[QTESLASecurityCategory.getSignatureSize(privateKey.getSecurityCategory())];

        switch (privateKey.getSecurityCategory())
        {
        case QTESLASecurityCategory.HEURISTIC_I:
            QTESLA.signingI(sig, message, 0, message.length, privateKey.getSecret(), secureRandom);
            break;
        case QTESLASecurityCategory.HEURISTIC_III_SIZE:
            QTESLA.signingIIISize(sig, message, 0, message.length, privateKey.getSecret(), secureRandom);
            break;
        case QTESLASecurityCategory.HEURISTIC_III_SPEED:
            QTESLA.signingIIISpeed(sig, message, 0, message.length, privateKey.getSecret(), secureRandom);
            break;
        case QTESLASecurityCategory.PROVABLY_SECURE_I:
            QTESLA.signingIP(sig, message, 0, message.length, privateKey.getSecret(), secureRandom);
            break;
        case QTESLASecurityCategory.PROVABLY_SECURE_III:
            QTESLA.signingIIIP(sig, message, 0, message.length, privateKey.getSecret(), secureRandom);
            break;
        default:
            throw new IllegalArgumentException("unknown security category: " + privateKey.getSecurityCategory());
        }

        return sig;
    }

    /**
     * Verify the signature against the passed in message.
     *
     * @param message the message that was supposed to have been signed.
     * @param signature the signature of the message
     * @return true if the signature passes, false otherwise.
     */
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        int status;

        switch (publicKey.getSecurityCategory())
        {
        case QTESLASecurityCategory.HEURISTIC_I:
            status = QTESLA.verifyingI(message, signature, 0, signature.length, publicKey.getPublicData());
            break;
        case QTESLASecurityCategory.HEURISTIC_III_SIZE:
            status = QTESLA.verifyingIIISize(message, signature, 0, signature.length, publicKey.getPublicData());
            break;
        case QTESLASecurityCategory.HEURISTIC_III_SPEED:
            status = QTESLA.verifyingIIISpeed(message, signature, 0, signature.length, publicKey.getPublicData());
            break;
        case QTESLASecurityCategory.PROVABLY_SECURE_I:
            status = QTESLA.verifyingPI(message, signature, 0, signature.length, publicKey.getPublicData());
            break;
        case QTESLASecurityCategory.PROVABLY_SECURE_III:
            status = QTESLA.verifyingPIII(message, signature, 0, signature.length, publicKey.getPublicData());
            break;
        default:
            throw new IllegalArgumentException("unknown security category: " + publicKey.getSecurityCategory());
        }

        return 0 == status;
    }
}
