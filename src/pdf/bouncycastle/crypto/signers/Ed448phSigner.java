package pdf.bouncycastle.crypto.signers;

import pdf.bouncycastle.crypto.CipherParameters;
import pdf.bouncycastle.crypto.Signer;
import pdf.bouncycastle.crypto.Xof;
import pdf.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import pdf.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import pdf.bouncycastle.math.ec.rfc8032.Ed448;
import pdf.bouncycastle.util.Arrays;

public class Ed448phSigner
    implements Signer
{
    private final Xof prehash = Ed448.createPrehash();
    private final byte[] context;

    private boolean forSigning;
    private Ed448PrivateKeyParameters privateKey;
    private Ed448PublicKeyParameters publicKey;

    public Ed448phSigner(byte[] context)
    {
        this.context = Arrays.clone(context);
    }

    public void init(boolean forSigning, CipherParameters parameters)
    {
        this.forSigning = forSigning;

        if (forSigning)
        {
            // TODO Allow AsymmetricCipherKeyPair to be a CipherParameters?

            this.privateKey = (Ed448PrivateKeyParameters)parameters;
            this.publicKey = privateKey.generatePublicKey();
        }
        else
        {
            this.privateKey = null;
            this.publicKey = (Ed448PublicKeyParameters)parameters;
        }

        reset();
    }

    public void update(byte b)
    {
        prehash.update(b);
    }

    public void update(byte[] buf, int off, int len)
    {
        prehash.update(buf, off, len);
    }

    public byte[] generateSignature()
    {
        if (!forSigning || null == privateKey)
        {
            throw new IllegalStateException("Ed448phSigner not initialised for signature generation.");
        }

        byte[] msg = new byte[Ed448.PREHASH_SIZE];
        if (Ed448.PREHASH_SIZE != prehash.doFinal(msg, 0, Ed448.PREHASH_SIZE))
        {
            throw new IllegalStateException("Prehash digest failed");
        }

        byte[] signature = new byte[Ed448PrivateKeyParameters.SIGNATURE_SIZE];
        privateKey.sign(Ed448.Algorithm.Ed448ph, publicKey, context, msg, 0, Ed448.PREHASH_SIZE, signature, 0);
        return signature;
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || null == publicKey)
        {
            throw new IllegalStateException("Ed448phSigner not initialised for verification");
        }
        if (Ed448.SIGNATURE_SIZE != signature.length)
        {
            return false;
        }

        byte[] pk = publicKey.getEncoded();
        return Ed448.verifyPrehash(signature, 0, pk, 0, context, prehash);
    }

    public void reset()
    {
        prehash.reset();
    }
}
