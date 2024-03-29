package pdf.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;

import pdf.bouncycastle.crypto.CipherParameters;
import pdf.bouncycastle.crypto.Signer;
import pdf.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import pdf.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import pdf.bouncycastle.math.ec.rfc8032.Ed25519;
import pdf.bouncycastle.util.Arrays;

public class Ed25519ctxSigner
    implements Signer
{
    private final Buffer buffer = new Buffer();
    private final byte[] context;

    private boolean forSigning;
    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters publicKey;

    public Ed25519ctxSigner(byte[] context)
    {
        this.context = Arrays.clone(context);
    }

    public void init(boolean forSigning, CipherParameters parameters)
    {
        this.forSigning = forSigning;

        if (forSigning)
        {
            // TODO Allow AsymmetricCipherKeyPair to be a CipherParameters?

            this.privateKey = (Ed25519PrivateKeyParameters)parameters;
            this.publicKey = privateKey.generatePublicKey();
        }
        else
        {
            this.privateKey = null;
            this.publicKey = (Ed25519PublicKeyParameters)parameters;
        }

        reset();
    }

    public void update(byte b)
    {
        buffer.write(b);
    }

    public void update(byte[] buf, int off, int len)
    {
        buffer.write(buf, off, len);
    }

    public byte[] generateSignature()
    {
        if (!forSigning || null == privateKey)
        {
            throw new IllegalStateException("Ed25519ctxSigner not initialised for signature generation.");
        }

        return buffer.generateSignature(privateKey, publicKey, context);
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || null == publicKey)
        {
            throw new IllegalStateException("Ed25519ctxSigner not initialised for verification");
        }

        return buffer.verifySignature(publicKey, context, signature);
    }

    public void reset()
    {
        buffer.reset();
    }

    private static class Buffer extends ByteArrayOutputStream
    {
        synchronized byte[] generateSignature(Ed25519PrivateKeyParameters privateKey, Ed25519PublicKeyParameters publicKey, byte[] ctx)
        {
            byte[] signature = new byte[Ed25519PrivateKeyParameters.SIGNATURE_SIZE];
            privateKey.sign(Ed25519.Algorithm.Ed25519ctx, publicKey, ctx, buf, 0, count, signature, 0);
            reset();
            return signature;
        }

        synchronized boolean verifySignature(Ed25519PublicKeyParameters publicKey, byte[] ctx, byte[] signature)
        {
            if (Ed25519.SIGNATURE_SIZE != signature.length)
            {
                return false;
            }

            byte[] pk = publicKey.getEncoded();
            boolean result = Ed25519.verify(signature, 0, pk, 0, ctx, buf, 0, count);
            reset();
            return result;
        }

        public synchronized void reset()
        {
            Arrays.fill(buf, 0, count, (byte)0);
            this.count = 0;
        }
    }
}
