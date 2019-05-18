package pdf.bouncycastle.operator.bc;

import pdf.bouncycastle.crypto.engines.AESWrapEngine;
import pdf.bouncycastle.crypto.params.KeyParameter;

public class BcAESSymmetricKeyUnwrapper
    extends BcSymmetricKeyUnwrapper
{
    public BcAESSymmetricKeyUnwrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}
