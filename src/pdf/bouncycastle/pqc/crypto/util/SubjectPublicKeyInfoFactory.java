package pdf.bouncycastle.pqc.crypto.util;

import java.io.IOException;

import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import pdf.bouncycastle.crypto.params.AsymmetricKeyParameter;
import pdf.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import pdf.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import pdf.bouncycastle.pqc.asn1.XMSSKeyParams;
import pdf.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import pdf.bouncycastle.pqc.asn1.XMSSMTPublicKey;
import pdf.bouncycastle.pqc.asn1.XMSSPublicKey;
import pdf.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import pdf.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import pdf.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import pdf.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import pdf.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;

/**
 * Factory to create ASN.1 subject public key info objects from lightweight public keys.
 */
public class SubjectPublicKeyInfoFactory
{
    private SubjectPublicKeyInfoFactory()
    {

    }

    /**
     * Create a SubjectPublicKeyInfo public key.
     *
     * @param publicKey the key to be encoded into the info object.
     * @return a SubjectPublicKeyInfo representing the key.
     * @throws java.io.IOException on an error encoding the key
     */
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        if (publicKey instanceof QTESLAPublicKeyParameters)
        {
            QTESLAPublicKeyParameters keyParams = (QTESLAPublicKeyParameters)publicKey;
            AlgorithmIdentifier algorithmIdentifier = Utils.qTeslaLookupAlgID(keyParams.getSecurityCategory());

            return new SubjectPublicKeyInfo(algorithmIdentifier, keyParams.getPublicData());
        }
        else if (publicKey instanceof SPHINCSPublicKeyParameters)
        {
            SPHINCSPublicKeyParameters params = (SPHINCSPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(params.getTreeDigest())));
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getKeyData());
        }
        else if (publicKey instanceof NHPublicKeyParameters)
        {
            NHPublicKeyParameters params = (NHPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getPubData());
        }
        else if (publicKey instanceof XMSSPublicKeyParameters)
        {
            XMSSPublicKeyParameters keyParams = (XMSSPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                new XMSSKeyParams(keyParams.getParameters().getHeight(), Utils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));
            return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSPublicKey(keyParams.getPublicSeed(), keyParams.getRoot()));
        }
        else if (publicKey instanceof XMSSMTPublicKeyParameters)
        {
            XMSSMTPublicKeyParameters keyParams = (XMSSMTPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(),
                Utils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));
            return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSMTPublicKey(keyParams.getPublicSeed(), keyParams.getRoot()));
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }
}
