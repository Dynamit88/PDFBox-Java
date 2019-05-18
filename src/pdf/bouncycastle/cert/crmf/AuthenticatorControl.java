package pdf.bouncycastle.cert.crmf;

import pdf.bouncycastle.asn1.ASN1Encodable;
import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.DERUTF8String;
import pdf.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;

/**
 * Carrier for an authenticator control.
 */
public class AuthenticatorControl
    implements Control
{
    private static final ASN1ObjectIdentifier type = CRMFObjectIdentifiers.id_regCtrl_authenticator;

    private final DERUTF8String token;

    /**
     * Basic constructor - build from a UTF-8 string representing the token.
     *
     * @param token UTF-8 string representing the token.
     */
    public AuthenticatorControl(DERUTF8String token)
    {
        this.token = token;
    }

    /**
     * Basic constructor - build from a string representing the token.
     *
     * @param token string representing the token.
     */
    public AuthenticatorControl(String token)
    {
        this.token = new DERUTF8String(token);
    }

    /**
     * Return the type of this control.
     *
     * @return CRMFObjectIdentifiers.id_regCtrl_authenticator
     */
    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    /**
     * Return the token associated with this control (a UTF8String).
     *
     * @return a UTF8String.
     */
    public ASN1Encodable getValue()
    {
        return token;
    }
}
