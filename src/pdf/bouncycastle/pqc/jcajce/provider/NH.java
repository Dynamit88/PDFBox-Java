package pdf.bouncycastle.pqc.jcajce.provider;

import pdf.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import pdf.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import pdf.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import pdf.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import pdf.bouncycastle.pqc.jcajce.provider.newhope.NHKeyFactorySpi;

public class NH
{
    private static final String PREFIX = "pdf.bouncycastle.pqc.jcajce.provider" + ".newhope.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.NH", PREFIX + "NHKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.NH", PREFIX + "NHKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyAgreement.NH", PREFIX + "KeyAgreementSpi");

            AsymmetricKeyInfoConverter keyFact = new NHKeyFactorySpi();

            registerOid(provider, PQCObjectIdentifiers.newHope, "NH", keyFact);
        }
    }
}
