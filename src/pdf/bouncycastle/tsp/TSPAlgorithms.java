package pdf.bouncycastle.tsp;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import pdf.bouncycastle.asn1.gm.GMObjectIdentifiers;
import pdf.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import pdf.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import pdf.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import pdf.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import pdf.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;

/**
 * Recognised hash algorithms for the time stamp protocol.
 */
public interface TSPAlgorithms
{
    public static final ASN1ObjectIdentifier MD5 = PKCSObjectIdentifiers.md5;

    public static final ASN1ObjectIdentifier SHA1 = OIWObjectIdentifiers.idSHA1;
    
    public static final ASN1ObjectIdentifier SHA224 = NISTObjectIdentifiers.id_sha224;
    public static final ASN1ObjectIdentifier SHA256 = NISTObjectIdentifiers.id_sha256;
    public static final ASN1ObjectIdentifier SHA384 = NISTObjectIdentifiers.id_sha384;
    public static final ASN1ObjectIdentifier SHA512 = NISTObjectIdentifiers.id_sha512;

    public static final ASN1ObjectIdentifier RIPEMD128 = TeleTrusTObjectIdentifiers.ripemd128;
    public static final ASN1ObjectIdentifier RIPEMD160 = TeleTrusTObjectIdentifiers.ripemd160;
    public static final ASN1ObjectIdentifier RIPEMD256 = TeleTrusTObjectIdentifiers.ripemd256;
    
    public static final ASN1ObjectIdentifier GOST3411 = CryptoProObjectIdentifiers.gostR3411;

    public static final ASN1ObjectIdentifier GOST3411_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;

    public static final ASN1ObjectIdentifier GOST3411_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512;

    public static final ASN1ObjectIdentifier SM3 = GMObjectIdentifiers.sm3;

    public static final Set    ALLOWED = new HashSet(Arrays.asList(new ASN1ObjectIdentifier[] { SM3, GOST3411, GOST3411_2012_256, GOST3411_2012_512, MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD128, RIPEMD160, RIPEMD256 }));
}
