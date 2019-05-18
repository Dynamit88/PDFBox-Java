package pdf.bouncycastle.jcajce.provider.symmetric.util;

import pdf.bouncycastle.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
