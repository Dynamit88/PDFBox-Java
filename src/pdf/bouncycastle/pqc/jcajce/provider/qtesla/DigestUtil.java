package pdf.bouncycastle.pqc.jcajce.provider.qtesla;

import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import pdf.bouncycastle.crypto.Digest;
import pdf.bouncycastle.crypto.Xof;
import pdf.bouncycastle.crypto.digests.SHA256Digest;
import pdf.bouncycastle.crypto.digests.SHA512Digest;
import pdf.bouncycastle.crypto.digests.SHAKEDigest;

class DigestUtil
{
    static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128))
        {
            return new SHAKEDigest(128);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }

    public static byte[] getDigestResult(Digest digest)
    {
        byte[] hash = new byte[DigestUtil.getDigestSize(digest)];

        if (digest instanceof Xof)
        {
            ((Xof)digest).doFinal(hash, 0, hash.length);
        }
        else
        {
            digest.doFinal(hash, 0);
        }

        return hash;
    }

    public static int getDigestSize(Digest digest)
    {
        if (digest instanceof Xof)
        {
            return digest.getDigestSize() * 2;
        }

        return digest.getDigestSize();
    }
}
