package pdf.bouncycastle.crypto.ec;

import pdf.bouncycastle.crypto.CipherParameters;
import pdf.bouncycastle.math.ec.ECPoint;

public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}
