package pdf.bouncycastle.jcajce.provider.symmetric;

import pdf.bouncycastle.crypto.CipherKeyGenerator;
import pdf.bouncycastle.crypto.engines.Grain128Engine;
import pdf.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import pdf.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class Grain128
{
    private Grain128()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new Grain128Engine(), 12);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Grain128", 128, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Grain128.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.Grain128", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.Grain128", PREFIX + "$KeyGen");
        }
    }
}
