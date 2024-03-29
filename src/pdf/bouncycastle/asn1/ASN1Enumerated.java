package pdf.bouncycastle.asn1;

import java.io.IOException;
import java.math.BigInteger;

import pdf.bouncycastle.util.Arrays;
import pdf.bouncycastle.util.Properties;

/**
 * Class representing the ASN.1 ENUMERATED type.
 */
public class ASN1Enumerated
    extends ASN1Primitive
{
    private final byte[] bytes;

    /**
     * return an enumerated from the passed in object
     *
     * @param obj an ASN1Enumerated or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Enumerated instance, or null.
     */
    public static ASN1Enumerated getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1Enumerated)
        {
            return (ASN1Enumerated)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1Enumerated)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an Enumerated from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1Enumerated instance, or null.
     */
    public static ASN1Enumerated getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof ASN1Enumerated)
        {
            return getInstance(o);
        }
        else
        {
            return fromOctetString(((ASN1OctetString)o).getOctets());
        }
    }

    /**
     * Constructor from int.
     *
     * @param value the value of this enumerated.
     */
    public ASN1Enumerated(
        int         value)
    {
        bytes = BigInteger.valueOf(value).toByteArray();
    }

    /**
     * Constructor from BigInteger
     *
     * @param value the value of this enumerated.
     */
    public ASN1Enumerated(
        BigInteger   value)
    {
        bytes = value.toByteArray();
    }

    /**
     * Constructor from encoded BigInteger.
     *
     * @param bytes the value of this enumerated as an encoded BigInteger (signed).
     */
    public ASN1Enumerated(
        byte[]   bytes)
    {
        if (!Properties.isOverrideSet("pdf.bouncycastle.asn1.allow_unsafe_integer"))
        {
            if (ASN1Integer.isMalformed(bytes))
            {
                throw new IllegalArgumentException("malformed enumerated");
            }
        }
        this.bytes = Arrays.clone(bytes);
    }

    public BigInteger getValue()
    {
        return new BigInteger(bytes);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(bytes.length) + bytes.length;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.ENUMERATED, bytes);
    }
    
    boolean asn1Equals(
        ASN1Primitive  o)
    {
        if (!(o instanceof ASN1Enumerated))
        {
            return false;
        }

        ASN1Enumerated other = (ASN1Enumerated)o;

        return Arrays.areEqual(this.bytes, other.bytes);
    }

    public int hashCode()
    {
        return Arrays.hashCode(bytes);
    }

    private static ASN1Enumerated[] cache = new ASN1Enumerated[12];

    static ASN1Enumerated fromOctetString(byte[] enc)
    {
        if (enc.length > 1)
        {
            return new ASN1Enumerated(enc);
        }

        if (enc.length == 0)
        {
            throw new IllegalArgumentException("ENUMERATED has zero length");
        }
        int value = enc[0] & 0xff;

        if (value >= cache.length)
        {
            return new ASN1Enumerated(Arrays.clone(enc));
        }

        ASN1Enumerated possibleMatch = cache[value];

        if (possibleMatch == null)
        {
            possibleMatch = cache[value] = new ASN1Enumerated(Arrays.clone(enc));
        }

        return possibleMatch;
    }
}
