package org.sufficientlysecure.keychain.testsupport;

import org.spongycastle.bcpg.CompressionAlgorithmTags;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.MPInteger;
import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.bcpg.PublicKeyPacket;
import org.spongycastle.bcpg.RSAPublicBCPGKey;
import org.spongycastle.bcpg.SignaturePacket;
import org.spongycastle.bcpg.SignatureSubpacket;
import org.spongycastle.bcpg.SignatureSubpacketTags;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.bcpg.UserIDPacket;
import org.spongycastle.bcpg.sig.Features;
import org.spongycastle.bcpg.sig.IssuerKeyID;
import org.spongycastle.bcpg.sig.KeyFlags;
import org.spongycastle.bcpg.sig.PreferredAlgorithms;
import org.spongycastle.bcpg.sig.SignatureCreationTime;
import org.spongycastle.bcpg.sig.SignatureExpirationTime;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;

import java.math.BigInteger;
import java.text.DateFormat;
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
        return ringForModulus(new Date(0), "user1@example.com");
    }

    public static UncachedKeyRing ring2() {
        return ringForModulus(new Date(0), "user1@example.com");
    }

    private static UncachedKeyRing ringForModulus(Date date, String userIdString) {

        try {
            PGPPublicKey publicKey = createPgpPublicKey(modulus, date);
            UserIDPacket userId = createUserId(userIdString);
            SignaturePacket signaturePacket = createSignaturePacket(date);

            byte[] publicKeyEncoded = publicKey.getEncoded();
            byte[] userIdEncoded = userId.getEncoded();
            byte[] signaturePacketEncoded = signaturePacket.getEncoded();
            byte[] encodedRing = TestDataUtil.concatAll(
                    publicKeyEncoded,
                    userIdEncoded,
                    signaturePacketEncoded);

            PGPPublicKeyRing pgpPublicKeyRing = new PGPPublicKeyRing(
                    encodedRing, new BcKeyFingerprintCalculator());

            return UncachedKeyRing.decodeFromData(pgpPublicKeyRing.getEncoded());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static SignaturePacket createSignaturePacket(Date date) {
        int signatureType = PGPSignature.POSITIVE_CERTIFICATION;
        long keyID = 1;
        int keyAlgorithm = SignaturePacket.RSA_GENERAL;
        int hashAlgorithm = HashAlgorithmTags.SHA1;

        SignatureSubpacket[] hashedData = new SignatureSubpacket[]{
                new SignatureCreationTime(true, date),
                new KeyFlags(true, KeyFlags.SIGN_DATA & KeyFlags.CERTIFY_OTHER),
                new SignatureExpirationTime(true, date.getTime()),
                new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_SYM_ALGS, true,
                        new int[]{SymmetricKeyAlgorithmTags.AES_256,
                                SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128,
                                SymmetricKeyAlgorithmTags.CAST5, SymmetricKeyAlgorithmTags.TRIPLE_DES}
                ),
                new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_HASH_ALGS, true,
                        new int[]{
                                HashAlgorithmTags.SHA256,
                                HashAlgorithmTags.SHA1,
                                HashAlgorithmTags.SHA384,
                                HashAlgorithmTags.SHA512,
                                HashAlgorithmTags.SHA224

                        }
                ),
                new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_COMP_ALGS, true,
                        new int[]{
                                CompressionAlgorithmTags.ZLIB,
                                CompressionAlgorithmTags.BZIP2,
                                CompressionAlgorithmTags.ZLIB
                        }
                ),
                new Features(false, Features.FEATURE_MODIFICATION_DETECTION),
                // can't do keyserver prefs


        };
        SignatureSubpacket[] unhashedData = new SignatureSubpacket[]{
                new IssuerKeyID(true, new BigInteger("15130BCF071AE6BF", 16).toByteArray())
        };
        byte[] fingerPrint = new BigInteger("522c", 16).toByteArray();
        MPInteger[] signature = new MPInteger[]{};
        return new SignaturePacket(signatureType,
                keyID,
                keyAlgorithm,
                hashAlgorithm,
                hashedData,
                unhashedData,
                fingerPrint,
                signature);
    }

    private static PGPPublicKey createPgpPublicKey(BigInteger modulus, Date date) throws PGPException {
        PublicKeyPacket publicKeyPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.RSA_SIGN, date, new RSAPublicBCPGKey(modulus, exponent));
        return new PGPPublicKey(
                publicKeyPacket, new BcKeyFingerprintCalculator());
    }

    private static UserIDPacket createUserId(String userId) {
        return new UserIDPacket(userId);
    }

}
