package pdf.bouncycastle.cert.crmf;

import java.io.IOException;
import java.io.OutputStream;

import pdf.bouncycastle.asn1.ASN1Encodable;
import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.DEROutputStream;
import pdf.bouncycastle.asn1.x509.ExtensionsGenerator;
import pdf.bouncycastle.cert.CertIOException;

class CRMFUtil
{
    static void derEncodeToStream(ASN1Encodable obj, OutputStream stream)
    {
        DEROutputStream dOut = new DEROutputStream(stream);

        try
        {
            dOut.writeObject(obj);

            dOut.close();
        }
        catch (IOException e)
        {
            throw new CRMFRuntimeException("unable to DER encode object: " + e.getMessage(), e);
        }
    }

    static void addExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value)
        throws CertIOException
    {
        try
        {
            extGenerator.addExtension(oid, isCritical, value);
        }
        catch (IOException e)
        {
            throw new CertIOException("cannot encode extension: " + e.getMessage(), e);
        }
    }
}
