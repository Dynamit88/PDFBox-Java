package pdf.bouncycastle.cms.bc;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import pdf.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import pdf.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import pdf.bouncycastle.asn1.x509.AlgorithmIdentifier;
import pdf.bouncycastle.cms.CMSAlgorithm;
import pdf.bouncycastle.cms.CMSException;
import pdf.bouncycastle.crypto.CipherKeyGenerator;
import pdf.bouncycastle.crypto.CipherParameters;
import pdf.bouncycastle.crypto.ExtendedDigest;
import pdf.bouncycastle.crypto.Wrapper;
import pdf.bouncycastle.crypto.digests.SHA1Digest;
import pdf.bouncycastle.crypto.digests.SHA224Digest;
import pdf.bouncycastle.crypto.digests.SHA256Digest;
import pdf.bouncycastle.crypto.digests.SHA384Digest;
import pdf.bouncycastle.crypto.digests.SHA512Digest;
import pdf.bouncycastle.crypto.engines.AESEngine;
import pdf.bouncycastle.crypto.engines.DESEngine;
import pdf.bouncycastle.crypto.engines.DESedeEngine;
import pdf.bouncycastle.crypto.engines.RC2Engine;
import pdf.bouncycastle.crypto.engines.RFC3211WrapEngine;
import pdf.bouncycastle.crypto.params.KeyParameter;
import pdf.bouncycastle.crypto.util.AlgorithmIdentifierFactory;
import pdf.bouncycastle.crypto.util.CipherFactory;
import pdf.bouncycastle.crypto.util.CipherKeyGeneratorFactory;
import pdf.bouncycastle.operator.OperatorCreationException;
import pdf.bouncycastle.operator.bc.BcDigestProvider;

class EnvelopedDataHelper
{
    protected static final Map BASE_CIPHER_NAMES = new HashMap();
    protected static final Map MAC_ALG_NAMES = new HashMap();

    private static final Map prfs = createTable();

    private static Map createTable()
    {
        Map table = new HashMap();

        table.put(PKCSObjectIdentifiers.id_hmacWithSHA1, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA1Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA224, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA224Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA256, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA256Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA384, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA384Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA512, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA512Digest();
            }
        });

        return Collections.unmodifiableMap(table);
    }

    static
    {
        BASE_CIPHER_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDE");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES128_CBC, "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES192_CBC, "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES256_CBC, "AES");

        MAC_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDEMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES128_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES192_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES256_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.RC2_CBC, "RC2Mac");
    }

    EnvelopedDataHelper()
    {
    }

    static ExtendedDigest getPRF(AlgorithmIdentifier algID)
        throws OperatorCreationException
    {
        return ((BcDigestProvider)prfs.get(algID.getAlgorithm())).get(null);
    }

    static Wrapper createRFC3211Wrapper(ASN1ObjectIdentifier algorithm)
        throws CMSException
    {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes192_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes256_CBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new AESEngine());
        }
        else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new DESedeEngine());
        }
        else if (OIWObjectIdentifiers.desCBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new DESEngine());
        }
        else if (PKCSObjectIdentifiers.RC2_CBC.equals(algorithm))
        {
            return new RFC3211WrapEngine(new RC2Engine());
        }
        else
        {
            throw new CMSException("cannot recognise wrapper: " + algorithm);
        }
    }

    static Object createContentCipher(boolean forEncryption, CipherParameters encKey, AlgorithmIdentifier encryptionAlgID)
        throws CMSException
    {
        try
        {
            return CipherFactory.createContentCipher(forEncryption, encKey, encryptionAlgID);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException(e.getMessage(), e);
        }
    }

    AlgorithmIdentifier generateEncryptionAlgID(ASN1ObjectIdentifier encryptionOID, KeyParameter encKey, SecureRandom random)
        throws CMSException
    {
        try
        {
            return AlgorithmIdentifierFactory.generateEncryptionAlgID(encryptionOID, encKey.getKey().length * 8, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException(e.getMessage(), e);
        }
    }

    CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm, SecureRandom random)
        throws CMSException
    {
        try
        {
            return CipherKeyGeneratorFactory.createKeyGenerator(algorithm, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException(e.getMessage(), e);
        }
    }
}
