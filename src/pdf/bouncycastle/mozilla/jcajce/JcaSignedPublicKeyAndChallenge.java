package pdf.bouncycastle.mozilla.jcajce;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import pdf.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import pdf.bouncycastle.jcajce.util.JcaJceHelper;
import pdf.bouncycastle.jcajce.util.NamedJcaJceHelper;
import pdf.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import pdf.bouncycastle.mozilla.SignedPublicKeyAndChallenge;

/**
 * This is designed to parse the SignedPublicKeyAndChallenge created by the
 * KEYGEN tag included by Mozilla based browsers.
 *  <pre>
 *  PublicKeyAndChallenge ::= SEQUENCE {
 *    spki SubjectPublicKeyInfo,
 *    challenge IA5STRING
 *  }
 *
 *  SignedPublicKeyAndChallenge ::= SEQUENCE {
 *    publicKeyAndChallenge PublicKeyAndChallenge,
 *    signatureAlgorithm AlgorithmIdentifier,
 *    signature BIT STRING
 *  }
 *  </pre>
 */
public class JcaSignedPublicKeyAndChallenge
    extends SignedPublicKeyAndChallenge
{
    JcaJceHelper helper = new DefaultJcaJceHelper();

    private JcaSignedPublicKeyAndChallenge(pdf.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge struct, JcaJceHelper helper)
    {
        super(struct);
        this.helper = helper;
    }

    public JcaSignedPublicKeyAndChallenge(byte[] bytes)
    {
        super(bytes);
    }

    public JcaSignedPublicKeyAndChallenge setProvider(String providerName)
    {
        return new JcaSignedPublicKeyAndChallenge(this.spkacSeq, new NamedJcaJceHelper(providerName));
    }

    public JcaSignedPublicKeyAndChallenge setProvider(Provider provider)
    {
        return new JcaSignedPublicKeyAndChallenge(this.spkacSeq, new ProviderJcaJceHelper(provider));
    }

    public PublicKey getPublicKey()
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        try
        {
            SubjectPublicKeyInfo subjectPublicKeyInfo = spkacSeq.getPublicKeyAndChallenge().getSubjectPublicKeyInfo();
            X509EncodedKeySpec xspec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
            

            AlgorithmIdentifier keyAlg = subjectPublicKeyInfo.getAlgorithm();

            KeyFactory factory = helper.createKeyFactory(keyAlg.getAlgorithm().getId());

            return factory.generatePublic(xspec);
        }
        catch (Exception e)
        {
            throw new InvalidKeyException("error encoding public key");
        }
    }
}
