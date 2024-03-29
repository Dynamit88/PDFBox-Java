package pdf.bouncycastle.pqc.asn1;

import java.math.BigInteger;

import pdf.bouncycastle.asn1.ASN1EncodableVector;
import pdf.bouncycastle.asn1.ASN1Integer;
import pdf.bouncycastle.asn1.ASN1Object;
import pdf.bouncycastle.asn1.ASN1Primitive;
import pdf.bouncycastle.asn1.ASN1Sequence;
import pdf.bouncycastle.asn1.ASN1TaggedObject;
import pdf.bouncycastle.asn1.DEROctetString;
import pdf.bouncycastle.asn1.DERSequence;
import pdf.bouncycastle.asn1.DERTaggedObject;
import pdf.bouncycastle.util.Arrays;

/**
 * XMMSMTPrivateKey
 * <pre>
 *     XMMSMTPrivateKey ::= SEQUENCE {
 *         version INTEGER -- 0
 *         keyData SEQUENCE {
 *            index         INTEGER
 *            secretKeySeed OCTET STRING
 *            secretKeyPRF  OCTET STRING
 *            publicSeed    OCTET STRING
 *            root          OCTET STRING
 *         }
 *         bdsState CHOICE {
 *            platformSerialization [0] OCTET STRING
 *         } OPTIONAL
 *    }
 * </pre>
 */
public class XMSSMTPrivateKey
    extends ASN1Object
{
    private final int index;
    private final byte[] secretKeySeed;
    private final byte[] secretKeyPRF;
    private final byte[] publicSeed;
    private final byte[] root;
    private final byte[] bdsState;

    public XMSSMTPrivateKey(int index, byte[] secretKeySeed, byte[] secretKeyPRF, byte[] publicSeed, byte[] root, byte[] bdsState)
    {
        this.index = index;
        this.secretKeySeed = Arrays.clone(secretKeySeed);
        this.secretKeyPRF = Arrays.clone(secretKeyPRF);
        this.publicSeed = Arrays.clone(publicSeed);
        this.root = Arrays.clone(root);
        this.bdsState = Arrays.clone(bdsState);
    }

    private XMSSMTPrivateKey(ASN1Sequence seq)
    {
        if (!ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().equals(BigInteger.valueOf(0)))
        {
            throw new IllegalArgumentException("unknown version of sequence");
        }

        if (seq.size() != 2 && seq.size() != 3)
        {
            throw new IllegalArgumentException("key sequence wrong size");
        }

        ASN1Sequence keySeq = ASN1Sequence.getInstance(seq.getObjectAt(1));

        this.index = ASN1Integer.getInstance(keySeq.getObjectAt(0)).getValue().intValue();
        this.secretKeySeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(1)).getOctets());
        this.secretKeyPRF = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(2)).getOctets());
        this.publicSeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(3)).getOctets());
        this.root = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(4)).getOctets());

        if(seq.size() == 3)
        {
            this.bdsState = Arrays.clone(DEROctetString.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(2)), true).getOctets());
        }
        else
        {
            this.bdsState = null;
        }
    }

    public static XMSSMTPrivateKey getInstance(Object o)
    {
        if (o instanceof XMSSMTPrivateKey)
        {
            return (XMSSMTPrivateKey)o;
        }
        else if (o != null)
        {
            return new XMSSMTPrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getIndex()
    {
        return index;
    }

    public byte[] getSecretKeySeed()
    {
        return Arrays.clone(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return Arrays.clone(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(root);
    }

    public byte[] getBdsState()
    {
        return Arrays.clone(bdsState);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(0)); // version

        ASN1EncodableVector vK = new ASN1EncodableVector();

        vK.add(new ASN1Integer(index));
        vK.add(new DEROctetString(secretKeySeed));
        vK.add(new DEROctetString(secretKeyPRF));
        vK.add(new DEROctetString(publicSeed));
        vK.add(new DEROctetString(root));

        v.add(new DERSequence(vK));
        v.add(new DERTaggedObject(true, 0, new DEROctetString(bdsState)));

        return new DERSequence(v);
    }
}
