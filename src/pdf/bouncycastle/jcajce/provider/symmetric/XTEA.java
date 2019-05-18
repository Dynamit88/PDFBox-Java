package pdf.bouncycastle.jcajce.provider.symmetric;

import pdf.bouncycastle.crypto.CipherKeyGenerator;
import pdf.bouncycastle.crypto.engines.XTEAEngine;
import pdf.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import pdf.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import pdf.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class XTEA
{
    private XTEA()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new XTEAEngine());
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("XTEA", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "XTEA IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = XTEA.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.XTEA", PREFIX + "$ECB");
            provider.addAlgorithm("KeyGenerator.XTEA", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.XTEA", PREFIX + "$AlgParams");

        }
    }
}
