package pdf.bouncycastle.crypto.params;

import java.security.SecureRandom;

import pdf.bouncycastle.crypto.KeyGenerationParameters;

public class Ed25519KeyGenerationParameters
    extends KeyGenerationParameters
{
    public Ed25519KeyGenerationParameters(SecureRandom random)
    {
        super(random, 256);
    }
}
