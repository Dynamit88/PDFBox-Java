package pdf.bouncycastle.pkix.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathBuilder;

import pdf.bouncycastle.jcajce.util.JcaJceHelper;

interface PKIXJcaJceHelper
    extends JcaJceHelper
{
    CertPathBuilder createCertPathBuilder(String type)
        throws NoSuchAlgorithmException, NoSuchProviderException;
}
