package pdf.bouncycastle.jcajce.provider.symmetric;

import pdf.bouncycastle.crypto.CipherKeyGenerator;
import pdf.bouncycastle.crypto.engines.Grainv1Engine;
import pdf.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import pdf.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import pdf.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class Grainv1
{
    private Grainv1()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new Grainv1Engine(), 8);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Grainv1", 80, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Grainv1 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Grainv1.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.Grainv1", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.Grainv1", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.Grainv1", PREFIX + "$AlgParams");
        }
    }
}
