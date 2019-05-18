package pdf.bouncycastle.pkcs.bc;

import java.io.IOException;

import pdf.bouncycastle.asn1.pkcs.CertificationRequest;
import pdf.bouncycastle.crypto.params.AsymmetricKeyParameter;
import pdf.bouncycastle.crypto.util.PublicKeyFactory;
import pdf.bouncycastle.pkcs.PKCS10CertificationRequest;
import pdf.bouncycastle.pkcs.PKCSException;

public class BcPKCS10CertificationRequest
    extends PKCS10CertificationRequest
{
    public BcPKCS10CertificationRequest(CertificationRequest certificationRequest)
    {
        super(certificationRequest);
    }

    public BcPKCS10CertificationRequest(byte[] encoding)
        throws IOException
    {
        super(encoding);
    }

    public BcPKCS10CertificationRequest(PKCS10CertificationRequest requestHolder)
    {
        super(requestHolder.toASN1Structure());
    }

    public AsymmetricKeyParameter getPublicKey()
        throws PKCSException
    {
        try
        {
            return PublicKeyFactory.createKey(this.getSubjectPublicKeyInfo());
        }
        catch (IOException e)
        {
            throw new PKCSException("error extracting key encoding: " + e.getMessage(), e);
        }
    }
}
