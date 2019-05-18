package pdf.bouncycastle.openssl;

import java.io.IOException;

interface PEMKeyPairParser
{
    PEMKeyPair parse(byte[] encoding)
        throws IOException;
}
