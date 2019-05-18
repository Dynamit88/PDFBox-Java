package pdf.bouncycastle.crypto.ec;

import pdf.bouncycastle.crypto.CipherParameters;
import pdf.bouncycastle.math.ec.ECPoint;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}
