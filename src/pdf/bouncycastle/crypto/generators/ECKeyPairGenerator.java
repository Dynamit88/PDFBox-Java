package pdf.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import pdf.bouncycastle.crypto.AsymmetricCipherKeyPair;
import pdf.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import pdf.bouncycastle.crypto.CryptoServicesRegistrar;
import pdf.bouncycastle.crypto.KeyGenerationParameters;
import pdf.bouncycastle.crypto.params.ECDomainParameters;
import pdf.bouncycastle.crypto.params.ECKeyGenerationParameters;
import pdf.bouncycastle.crypto.params.ECPrivateKeyParameters;
import pdf.bouncycastle.crypto.params.ECPublicKeyParameters;
import pdf.bouncycastle.math.ec.ECConstants;
import pdf.bouncycastle.math.ec.ECMultiplier;
import pdf.bouncycastle.math.ec.ECPoint;
import pdf.bouncycastle.math.ec.FixedPointCombMultiplier;
import pdf.bouncycastle.math.ec.WNafUtil;
import pdf.bouncycastle.util.BigIntegers;

public class ECKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator, ECConstants
{
    ECDomainParameters  params;
    SecureRandom        random;

    public void init(
        KeyGenerationParameters param)
    {
        ECKeyGenerationParameters  ecP = (ECKeyGenerationParameters)param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();

        if (this.random == null)
        {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }
    }

    /**
     * Given the domain parameters this routine generates an EC key
     * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger n = params.getN();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;

        BigInteger d;
        for (;;)
        {
            d = BigIntegers.createRandomBigInteger(nBitLength, random);

            if (d.compareTo(TWO) < 0  || (d.compareTo(n) >= 0))
            {
                continue;
            }

            if (WNafUtil.getNafWeight(d) < minWeight)
            {
                continue;
            }

            break;
        }

        ECPoint Q = createBasePointMultiplier().multiply(params.getG(), d);

        return new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(Q, params),
            new ECPrivateKeyParameters(d, params));
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
