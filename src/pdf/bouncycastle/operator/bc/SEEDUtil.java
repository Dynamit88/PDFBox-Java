package pdf.bouncycastle.operator.bc;

import pdf.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;

class SEEDUtil
{
    static AlgorithmIdentifier determineKeyEncAlg()
    {
        // parameters absent
        return new AlgorithmIdentifier(
            KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
    }
}
