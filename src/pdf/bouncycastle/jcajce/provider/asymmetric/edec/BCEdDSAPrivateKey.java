package pdf.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import pdf.bouncycastle.asn1.ASN1Encodable;
import pdf.bouncycastle.asn1.ASN1OctetString;
import pdf.bouncycastle.asn1.ASN1Set;
import pdf.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import pdf.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import pdf.bouncycastle.crypto.params.AsymmetricKeyParameter;
import pdf.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import pdf.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import pdf.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import pdf.bouncycastle.jcajce.interfaces.EdDSAKey;
import pdf.bouncycastle.util.Arrays;

public class BCEdDSAPrivateKey
    implements EdDSAKey, PrivateKey
{
    static final long serialVersionUID = 1L;
    
    private transient AsymmetricKeyParameter eddsaPrivateKey;

    private final boolean hasPublicKey;
    private final byte[] attributes;

    BCEdDSAPrivateKey(AsymmetricKeyParameter privKey)
    {
        this.hasPublicKey = true;
        this.attributes = null;
        this.eddsaPrivateKey = privKey;
    }

    BCEdDSAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.hasPublicKey = keyInfo.hasPublicKey();
        this.attributes = (keyInfo.getAttributes() != null) ? keyInfo.getAttributes().getEncoded() : null;

        populateFromPrivateKeyInfo(keyInfo);
    }

    private void populateFromPrivateKeyInfo(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1Encodable keyOcts = keyInfo.parsePrivateKey();
        if (EdECObjectIdentifiers.id_Ed448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
        {
            eddsaPrivateKey = new Ed448PrivateKeyParameters(ASN1OctetString.getInstance(keyOcts).getOctets(), 0);
        }
        else
        {
            eddsaPrivateKey = new Ed25519PrivateKeyParameters(ASN1OctetString.getInstance(keyOcts).getOctets(), 0);
        }
    }

    public String getAlgorithm()
    {
        return (eddsaPrivateKey instanceof Ed448PrivateKeyParameters) ? "Ed448" : "Ed25519";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        try
        {
            ASN1Set attrSet = ASN1Set.getInstance(attributes);
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(eddsaPrivateKey, attrSet);

            if (hasPublicKey)
            {
                return privInfo.getEncoded();
            }
            else
            {
                return new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(), privInfo.parsePrivateKey(), attrSet).getEncoded();
            }
        }
        catch (IOException e)
        {
            return null;
        }
    }

    AsymmetricKeyParameter engineGetKeyParameters()
    {
        return eddsaPrivateKey;
    }

    public String toString()
    {
        AsymmetricKeyParameter pubKey;
        if (eddsaPrivateKey instanceof Ed448PrivateKeyParameters)
        {
            pubKey = ((Ed448PrivateKeyParameters)eddsaPrivateKey).generatePublicKey();
        }
        else
        {
            pubKey = ((Ed25519PrivateKeyParameters)eddsaPrivateKey).generatePublicKey();
        }
        return Utils.keyToString("Private Key", getAlgorithm(), pubKey);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof BCEdDSAPrivateKey))
        {
            return false;
        }

        BCEdDSAPrivateKey other = (BCEdDSAPrivateKey)o;

        return Arrays.areEqual(other.getEncoded(), this.getEncoded());
    }

    public int hashCode()
    {
        return Arrays.hashCode(this.getEncoded());
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPrivateKeyInfo(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
