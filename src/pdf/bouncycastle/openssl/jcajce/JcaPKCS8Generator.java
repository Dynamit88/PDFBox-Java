package pdf.bouncycastle.openssl.jcajce;

import java.security.PrivateKey;

import pdf.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import pdf.bouncycastle.openssl.PKCS8Generator;
import pdf.bouncycastle.operator.OutputEncryptor;
import pdf.bouncycastle.util.io.pem.PemGenerationException;

public class JcaPKCS8Generator
    extends PKCS8Generator
{
    public JcaPKCS8Generator(PrivateKey key, OutputEncryptor encryptor)
         throws PemGenerationException
    {
         super(PrivateKeyInfo.getInstance(key.getEncoded()), encryptor);
    }
}
