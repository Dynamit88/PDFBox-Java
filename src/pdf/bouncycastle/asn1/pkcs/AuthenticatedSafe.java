package pdf.bouncycastle.asn1.pkcs;

import pdf.bouncycastle.asn1.ASN1EncodableVector;
import pdf.bouncycastle.asn1.ASN1Object;
import pdf.bouncycastle.asn1.ASN1Primitive;
import pdf.bouncycastle.asn1.ASN1Sequence;
import pdf.bouncycastle.asn1.BERSequence;
import pdf.bouncycastle.asn1.DLSequence;

public class AuthenticatedSafe
    extends ASN1Object
{
    private ContentInfo[]    info;
    private boolean  isBer = true;

    private AuthenticatedSafe(
        ASN1Sequence  seq)
    {
        info = new ContentInfo[seq.size()];

        for (int i = 0; i != info.length; i++)
        {
            info[i] = ContentInfo.getInstance(seq.getObjectAt(i));
        }

        isBer = seq instanceof BERSequence;
    }

    public static AuthenticatedSafe getInstance(
        Object o)
    {
        if (o instanceof AuthenticatedSafe)
        {
            return (AuthenticatedSafe)o;
        }

        if (o != null)
        {
            return new AuthenticatedSafe(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AuthenticatedSafe(
        ContentInfo[]       info)
    {
        this.info = copy(info);
    }

    public ContentInfo[] getContentInfo()
    {
        return copy(info);
    }

    private ContentInfo[] copy(ContentInfo[] infos)
    {
        ContentInfo[] tmp = new ContentInfo[infos.length];

        System.arraycopy(infos, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != info.length; i++)
        {
            v.add(info[i]);
        }

        if (isBer)
        {
            return new BERSequence(v);
        }
        else
        {
            return new DLSequence(v);
        }
    }
}
