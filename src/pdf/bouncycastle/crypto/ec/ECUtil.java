package pdf.bouncycastle.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;

import pdf.bouncycastle.math.ec.ECConstants;
import pdf.bouncycastle.util.BigIntegers;

class ECUtil
{
    static BigInteger generateK(BigInteger n, SecureRandom random)
    {
        int nBitLength = n.bitLength();
        BigInteger k;
        do
        {
            k = BigIntegers.createRandomBigInteger(nBitLength, random);
        }
        while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0));
        return k;
    }
}
