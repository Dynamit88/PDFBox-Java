package pdf.bouncycastle.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import pdf.bouncycastle.crypto.BlockCipher;
import pdf.bouncycastle.crypto.BufferedBlockCipher;
import pdf.bouncycastle.crypto.CipherKeyGenerator;
import pdf.bouncycastle.crypto.CryptoServicesRegistrar;
import pdf.bouncycastle.crypto.engines.RC6Engine;
import pdf.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import pdf.bouncycastle.crypto.macs.GMac;
import pdf.bouncycastle.crypto.modes.CBCBlockCipher;
import pdf.bouncycastle.crypto.modes.CFBBlockCipher;
import pdf.bouncycastle.crypto.modes.GCMBlockCipher;
import pdf.bouncycastle.crypto.modes.OFBBlockCipher;
import pdf.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import pdf.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import pdf.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class RC6
{
    private RC6()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new RC6Engine();
                }
            });
        }
    }

    public static class CBC
       extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new RC6Engine()), 128);
        }
    }

    static public class CFB
        extends BaseBlockCipher
    {
        public CFB()
        {
            super(new BufferedBlockCipher(new CFBBlockCipher(new RC6Engine(), 128)), 128);
        }
    }

    static public class OFB
        extends BaseBlockCipher
    {
        public OFB()
        {
            super(new BufferedBlockCipher(new OFBBlockCipher(new RC6Engine(), 128)), 128);
        }
    }

    public static class GMAC
        extends BaseMac
    {
        public GMAC()
        {
            super(new GMac(new GCMBlockCipher(new RC6Engine())));
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new pdf.bouncycastle.crypto.macs.Poly1305(new RC6Engine()));
        }
    }

    public static class Poly1305KeyGen
        extends BaseKeyGenerator
    {
        public Poly1305KeyGen()
        {
            super("Poly1305-RC6", 256, new Poly1305KeyGenerator());
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("RC6", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for RC6 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[]  iv = new byte[16];

            if (random == null)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = createParametersInstance("RC6");
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "RC6 IV";
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = RC6.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.RC6", PREFIX + "$ECB");
            provider.addAlgorithm("KeyGenerator.RC6", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.RC6", PREFIX + "$AlgParams");

            addGMacAlgorithm(provider, "RC6", PREFIX + "$GMAC", PREFIX + "$KeyGen");
            addPoly1305Algorithm(provider, "RC6", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
        }
    }
}
