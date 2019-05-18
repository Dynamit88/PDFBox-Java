package pdf.bouncycastle.crypto.tls;

import java.io.IOException;

import pdf.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface TlsAgreementCredentials
    extends TlsCredentials
{
    byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey)
        throws IOException;
}
