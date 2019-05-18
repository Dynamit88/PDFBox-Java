package pdf.bouncycastle.jcajce.provider.util;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import pdf.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import pdf.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public interface AsymmetricKeyInfoConverter
{
    PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException;

    PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException;
}
