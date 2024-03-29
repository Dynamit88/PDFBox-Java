package pdf.bouncycastle.pqc.crypto.xmss;

import java.util.HashMap;
import java.util.Map;

import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import pdf.bouncycastle.crypto.Digest;
import pdf.bouncycastle.crypto.Xof;
import pdf.bouncycastle.crypto.digests.SHA256Digest;
import pdf.bouncycastle.crypto.digests.SHA512Digest;
import pdf.bouncycastle.crypto.digests.SHAKEDigest;

class DigestUtil
{
    private static Map<String, ASN1ObjectIdentifier> nameToOid = new HashMap<String, ASN1ObjectIdentifier>();

    static
    {
        nameToOid.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        nameToOid.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        nameToOid.put("SHAKE128", NISTObjectIdentifiers.id_shake128);
        nameToOid.put("SHAKE256", NISTObjectIdentifiers.id_shake256);
    }

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

    static ASN1ObjectIdentifier getDigestOID(String name)
    {
        ASN1ObjectIdentifier oid = nameToOid.get(name);
        if (oid != null)
        {
            return oid;
        }

        throw new IllegalArgumentException("unrecognized digest name: " + name);
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
