package pdf.bouncycastle.jce.interfaces;

import javax.crypto.interfaces.DHKey;

import pdf.bouncycastle.jce.spec.ElGamalParameterSpec;

public interface ElGamalKey
    extends DHKey
{
    public ElGamalParameterSpec getParameters();
}
