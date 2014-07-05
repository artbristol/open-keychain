package org.sufficientlysecure.keychain.testsupport;

import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.bcpg.PublicKeyPacket;
import org.spongycastle.bcpg.RSAPublicBCPGKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;

/**
 * Created by art on 05/07/14.
 */
public class KeyringBuilder {


    private static final BigInteger modulus = new BigInteger(
            "cbab78d90d5f2cc0c54dd3c3953005a1" +
                    "e6b521f1ffa5465a102648bf7b91ec72" +
                    "f9c180759301587878caeb7333215620" +
                    "9f81ca5b3b94309d96110f6972cfc56a" +
                    "37fd6279f61d71f19b8f64b288e33829" +
                    "9dce133520f5b9b4253e6f4ba31ca36a" +
                    "fd87c2081b15f0b283e9350e370e181a" +
                    "23d31379101f17a23ae9192250db6540" +
                    "2e9cab2a275bc5867563227b197c8b13" +
                    "6c832a94325b680e144ed864fb00b9b8" +
                    "b07e13f37b40d5ac27dae63cd6a470a7" +
                    "b40fa3c7479b5b43e634850cc680b177" +
                    "8dd6b1b51856f36c3520f258f104db2f" +
                    "96b31a53dd74f708ccfcefccbe420a90" +
                    "1c37f1f477a6a4b15f5ecbbfd93311a6" +
                    "47bcc3f5f81c59dfe7252e3cd3be6e27"
            , 16
    );

    private static final BigInteger exponent = new BigInteger("010001", 16);

    public static UncachedKeyRing ring1() {
        return ringForModulus(modulus, new Date());
    }

    public static UncachedKeyRing ring2() {
        return ringForModulus(modulus, new Date());
    }

    private static UncachedKeyRing ringForModulus(BigInteger modulus, Date date) {

        try {
            PublicKeyPacket publicKeyPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.RSA_SIGN, date, new RSAPublicBCPGKey(modulus, exponent));
            PGPPublicKey publicKey = new PGPPublicKey(
                    publicKeyPacket, new BcKeyFingerprintCalculator());
            PGPPublicKeyRing pgpPublicKeyRing2 = new PGPPublicKeyRing(Arrays.asList(publicKey));
            return UncachedKeyRing.decodeFromData(pgpPublicKeyRing2.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
