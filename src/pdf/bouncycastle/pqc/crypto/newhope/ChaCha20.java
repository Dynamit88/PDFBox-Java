package pdf.bouncycastle.pqc.crypto.newhope;

import pdf.bouncycastle.crypto.engines.ChaChaEngine;
import pdf.bouncycastle.crypto.params.KeyParameter;
import pdf.bouncycastle.crypto.params.ParametersWithIV;

class ChaCha20
{
    static void process(byte[] key, byte[] nonce, byte[] buf, int off, int len)
    {
        ChaChaEngine e = new ChaChaEngine(20);
        e.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        e.processBytes(buf, off, len, buf, off);
    }
}
