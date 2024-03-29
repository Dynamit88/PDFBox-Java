package pdf.bouncycastle.pqc.jcajce.provider.qtesla;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import pdf.bouncycastle.crypto.AsymmetricCipherKeyPair;
import pdf.bouncycastle.crypto.CryptoServicesRegistrar;
import pdf.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import pdf.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import pdf.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import pdf.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import pdf.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import pdf.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;
import pdf.bouncycastle.util.Integers;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static final Map catLookup = new HashMap();

    static
    {
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_I), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_I));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SIZE), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_III_SIZE));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SPEED), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_III_SPEED));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_I), Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_I));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_III), Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_III));
    }

    private QTESLAKeyGenerationParameters param;
    private QTESLAKeyPairGenerator engine = new QTESLAKeyPairGenerator();

    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("qTESLA");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof QTESLAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a QTESLAParameterSpec");
        }

        QTESLAParameterSpec qteslaParams = (QTESLAParameterSpec)params;

        param = new QTESLAKeyGenerationParameters(((Integer)catLookup.get(qteslaParams.getSecurityCategory())).intValue(), random);

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new QTESLAKeyGenerationParameters(QTESLASecurityCategory.PROVABLY_SECURE_I, random);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        QTESLAPublicKeyParameters pub = (QTESLAPublicKeyParameters)pair.getPublic();
        QTESLAPrivateKeyParameters priv = (QTESLAPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCqTESLAPublicKey(pub), new BCqTESLAPrivateKey(priv));
    }
}
