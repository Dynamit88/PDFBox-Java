package pdf.bouncycastle.openssl.bc;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import pdf.bouncycastle.asn1.ASN1ObjectIdentifier;
import pdf.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import pdf.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import pdf.bouncycastle.crypto.BlockCipher;
import pdf.bouncycastle.crypto.BufferedBlockCipher;
import pdf.bouncycastle.crypto.PBEParametersGenerator;
import pdf.bouncycastle.crypto.digests.SHA1Digest;
import pdf.bouncycastle.crypto.engines.AESEngine;
import pdf.bouncycastle.crypto.engines.BlowfishEngine;
import pdf.bouncycastle.crypto.engines.DESEngine;
import pdf.bouncycastle.crypto.engines.DESedeEngine;
import pdf.bouncycastle.crypto.engines.RC2Engine;
import pdf.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import pdf.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import pdf.bouncycastle.crypto.modes.CBCBlockCipher;
import pdf.bouncycastle.crypto.modes.CFBBlockCipher;
import pdf.bouncycastle.crypto.modes.OFBBlockCipher;
import pdf.bouncycastle.crypto.paddings.BlockCipherPadding;
import pdf.bouncycastle.crypto.paddings.PKCS7Padding;
import pdf.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import pdf.bouncycastle.crypto.params.KeyParameter;
import pdf.bouncycastle.crypto.params.ParametersWithIV;
import pdf.bouncycastle.crypto.params.RC2Parameters;
import pdf.bouncycastle.openssl.EncryptionException;
import pdf.bouncycastle.openssl.PEMException;
import pdf.bouncycastle.util.Integers;

class PEMUtilities
{
    private static final Map KEYSIZES = new HashMap();
    private static final Set PKCS5_SCHEME_1 = new HashSet();
    private static final Set PKCS5_SCHEME_2 = new HashSet();

    static
    {
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC);

        PKCS5_SCHEME_2.add(PKCSObjectIdentifiers.id_PBES2);
        PKCS5_SCHEME_2.add(PKCSObjectIdentifiers.des_EDE3_CBC);
        PKCS5_SCHEME_2.add(NISTObjectIdentifiers.id_aes128_CBC);
        PKCS5_SCHEME_2.add(NISTObjectIdentifiers.id_aes192_CBC);
        PKCS5_SCHEME_2.add(NISTObjectIdentifiers.id_aes256_CBC);

        KEYSIZES.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), Integers.valueOf(192));
        KEYSIZES.put(NISTObjectIdentifiers.id_aes128_CBC.getId(), Integers.valueOf(128));
        KEYSIZES.put(NISTObjectIdentifiers.id_aes192_CBC.getId(), Integers.valueOf(192));
        KEYSIZES.put(NISTObjectIdentifiers.id_aes256_CBC.getId(), Integers.valueOf(256));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4.getId(), Integers.valueOf(128));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4, Integers.valueOf(40));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC, Integers.valueOf(128));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, Integers.valueOf(192));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC, Integers.valueOf(128));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, Integers.valueOf(40));
    }

    static int getKeySize(String algorithm)
    {
        if (!KEYSIZES.containsKey(algorithm))
        {
            throw new IllegalStateException("no key size for algorithm: " + algorithm);
        }
        
        return ((Integer)KEYSIZES.get(algorithm)).intValue();
    }

    static boolean isPKCS5Scheme1(ASN1ObjectIdentifier algOid)
    {
        return PKCS5_SCHEME_1.contains(algOid);
    }

    static boolean isPKCS5Scheme2(ASN1ObjectIdentifier algOid)
    {
        return PKCS5_SCHEME_2.contains(algOid);
    }

    public static boolean isPKCS12(ASN1ObjectIdentifier algOid)
    {
        return algOid.getId().startsWith(PKCSObjectIdentifiers.pkcs_12PbeIds.getId());
    }

    public static KeyParameter generateSecretKeyForPKCS5Scheme2(String algorithm, char[] password, byte[] salt, int iterationCount)
    {
        PBEParametersGenerator paramsGen = new PKCS5S2ParametersGenerator(new SHA1Digest());

        paramsGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, iterationCount);

        return (KeyParameter)paramsGen.generateDerivedParameters(PEMUtilities.getKeySize(algorithm));
    }

    static byte[] crypt(
        boolean encrypt,
        byte[]  bytes,
        char[]  password,
        String  dekAlgName,
        byte[]  iv)
        throws PEMException
    {
        byte[]             ivValue = iv;
        String             blockMode = "CBC";
        BlockCipher        engine;
        BlockCipherPadding padding = new PKCS7Padding();
        KeyParameter       sKey;

        // Figure out block mode and padding.
        if (dekAlgName.endsWith("-CFB"))
        {
            blockMode = "CFB";
            padding = null;
        }
        if (dekAlgName.endsWith("-ECB") ||
            "DES-EDE".equals(dekAlgName) ||
            "DES-EDE3".equals(dekAlgName))
        {
            // ECB is actually the default (though seldom used) when OpenSSL
            // uses DES-EDE (des2) or DES-EDE3 (des3).
            blockMode = "ECB";
            ivValue = null;
        }
        if (dekAlgName.endsWith("-OFB"))
        {
            blockMode = "OFB";
            padding = null;
        }

        // Figure out algorithm and key size.
        if (dekAlgName.startsWith("DES-EDE"))
        {
            // "DES-EDE" is actually des2 in OpenSSL-speak!
            // "DES-EDE3" is des3.
            boolean des2 = !dekAlgName.startsWith("DES-EDE3");
            sKey = getKey(password, 24, iv, des2);
            engine = new DESedeEngine();
        }
        else if (dekAlgName.startsWith("DES-"))
        {
            sKey = getKey(password, 8, iv);
            engine = new DESEngine();
        }
        else if (dekAlgName.startsWith("BF-"))
        {
            sKey = getKey(password, 16, iv);
            engine = new BlowfishEngine();
        }
        else if (dekAlgName.startsWith("RC2-"))
        {
            int keyBits = 128;
            if (dekAlgName.startsWith("RC2-40-"))
            {
                keyBits = 40;
            }
            else if (dekAlgName.startsWith("RC2-64-"))
            {
                keyBits = 64;
            }
            sKey = new RC2Parameters(getKey(password, keyBits / 8, iv).getKey(), keyBits);;
            engine = new RC2Engine();
        }
        else if (dekAlgName.startsWith("AES-"))
        {
            byte[] salt = iv;
            if (salt.length > 8)
            {
                salt = new byte[8];
                System.arraycopy(iv, 0, salt, 0, 8);
            }

            int keyBits;
            if (dekAlgName.startsWith("AES-128-"))
            {
                keyBits = 128;
            }
            else if (dekAlgName.startsWith("AES-192-"))
            {
                keyBits = 192;
            }
            else if (dekAlgName.startsWith("AES-256-"))
            {
                keyBits = 256;
            }
            else
            {
                throw new EncryptionException("unknown AES encryption with private key: " + dekAlgName);
            }
            sKey = getKey(password, keyBits / 8, salt);
            engine = new AESEngine();
        }
        else
        {
            throw new EncryptionException("unknown encryption with private key: " + dekAlgName);
        }

        if (blockMode.equals("CBC"))
        {
            engine = new CBCBlockCipher(engine);
        }
        else if (blockMode.equals("CFB"))
        {
            engine = new CFBBlockCipher(engine, engine.getBlockSize() * 8);
        }
        else if (blockMode.equals("OFB"))
        {
            engine = new OFBBlockCipher(engine, engine.getBlockSize() * 8);
        }

        try
        {
            BufferedBlockCipher c;
            if (padding == null)
            {
                c = new BufferedBlockCipher(engine);
            }
            else
            {
                c = new PaddedBufferedBlockCipher(engine, padding);
            }

            if (ivValue == null) // ECB block mode
            {
                c.init(encrypt, sKey);
            }
            else
            {
                c.init(encrypt, new ParametersWithIV(sKey, ivValue));
            }

            byte[] out = new byte[c.getOutputSize(bytes.length)];

            int procLen = c.processBytes(bytes, 0, bytes.length, out, 0);

            procLen += c.doFinal(out, procLen);

            if (procLen == out.length)
            {
                return out;
            }
            else
            {
                byte[] rv = new byte[procLen];

                System.arraycopy(out, 0, rv, 0, procLen);

                return rv;
            }
        }
        catch (Exception e)
        {
            throw new EncryptionException("exception using cipher - please check password and data.", e);
        }
    }

    private static KeyParameter getKey(
        char[]  password,
        int     keyLength,
        byte[]  salt)
        throws PEMException
    {
        return getKey(password, keyLength, salt, false);
    }

    private static KeyParameter getKey(
        char[]  password,
        int     keyLength,
        byte[]  salt,
        boolean des2)
        throws PEMException
    {
        PBEParametersGenerator paramsGen = new OpenSSLPBEParametersGenerator();

        paramsGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, 1);

        KeyParameter kp = (KeyParameter)paramsGen.generateDerivedParameters(keyLength * 8);

        if (des2 && kp.getKey().length == 24)
        {
            // For DES2, we must copy first 8 bytes into the last 8 bytes.
            byte[] key = kp.getKey();

            System.arraycopy(key, 0, key, 16, 8);

            return new KeyParameter(key);
        }

        return kp;
    }
}
