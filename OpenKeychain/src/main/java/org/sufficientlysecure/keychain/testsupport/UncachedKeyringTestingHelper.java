package org.sufficientlysecure.keychain.testsupport;

import org.spongycastle.bcpg.BCPGKey;
import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.bcpg.PublicKeyPacket;
import org.spongycastle.bcpg.RSAPublicBCPGKey;
import org.spongycastle.bcpg.SignatureSubpacket;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureSubpacketVector;
import org.spongycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.pgp.UncachedPublicKey;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;

/**
 * Created by art on 28/06/14.
 */
public class UncachedKeyringTestingHelper {
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

    public static boolean compareRing(UncachedKeyRing keyRing1, UncachedKeyRing keyRing2) {
        return TestDataUtil.iterEquals(keyRing1.getPublicKeys(), keyRing2.getPublicKeys(), new
                TestDataUtil.EqualityChecker<UncachedPublicKey>() {
                    @Override
                    public boolean areEquals(UncachedPublicKey lhs, UncachedPublicKey rhs) {
                        return comparePublicKey(lhs, rhs);
                    }
                });
    }

    public static boolean comparePublicKey(UncachedPublicKey key1, UncachedPublicKey key2) {
        boolean equal = true;

        if (key1.canAuthenticate() != key2.canAuthenticate()) {
            return false;
        }
        if (key1.canCertify() != key2.canCertify()) {
            return false;
        }
        if (key1.canEncrypt() != key2.canEncrypt()) {
            return false;
        }
        if (key1.canSign() != key2.canSign()) {
            return false;
        }
        if (key1.getAlgorithm() != key2.getAlgorithm()) {
            return false;
        }
        if (key1.getBitStrength() != key2.getBitStrength()) {
            return false;
        }
        if (!TestDataUtil.equals(key1.getCreationTime(), key2.getCreationTime())) {
            return false;
        }
        if (!TestDataUtil.equals(key1.getExpiryTime(), key2.getExpiryTime())) {
            return false;
        }
        if (!Arrays.equals(key1.getFingerprint(), key2.getFingerprint())) {
            return false;
        }
        if (key1.getKeyId() != key2.getKeyId()) {
            return false;
        }
        if (key1.getKeyUsage() != key2.getKeyUsage()) {
            return false;
        }
        if (!TestDataUtil.equals(key1.getPrimaryUserId(), key2.getPrimaryUserId())) {
            return false;
        }

        if (!keysAreEqual(key1.getPublicKey(), key2.getPublicKey())) {
            return false;
        }

        return equal;
    }

    public static boolean keysAreEqual(PGPPublicKey a, PGPPublicKey b) {

        if (a.getAlgorithm() != b.getAlgorithm()) {
            return false;
        }

        if (a.getBitStrength() != b.getBitStrength()) {
            return false;
        }

        if (!TestDataUtil.equals(a.getCreationTime(), b.getCreationTime())) {
            return false;
        }

        if (!Arrays.equals(a.getFingerprint(), b.getFingerprint())) {
            return false;
        }

        if (a.getKeyID() != b.getKeyID()) {
            return false;
        }

        if (!pubKeyPacketsAreEqual(a.getPublicKeyPacket(), b.getPublicKeyPacket())) {
            return false;
        }

        if (a.getVersion() != b.getVersion()) {
            return false;
        }

        if (a.getValidDays() != b.getValidDays()) {
            return false;
        }

        if (a.getValidSeconds() != b.getValidSeconds()) {
            return false;
        }

        if (!Arrays.equals(a.getTrustData(), b.getTrustData())) {
            return false;
        }

        if (!TestDataUtil.iterEquals(a.getUserIDs(), b.getUserIDs())) {
            return false;
        }

        if (!TestDataUtil.iterEquals(a.getUserAttributes(), b.getUserAttributes(),
                new TestDataUtil.EqualityChecker<PGPUserAttributeSubpacketVector>() {
                    public boolean areEquals(PGPUserAttributeSubpacketVector lhs, PGPUserAttributeSubpacketVector rhs) {
                        // For once, BC defines equals, so we use it implicitly.
                        return TestDataUtil.equals(lhs, rhs);
                    }
                }
        )) {
            return false;
        }


        if (!TestDataUtil.iterEquals(a.getSignatures(), b.getSignatures(),
                new TestDataUtil.EqualityChecker<PGPSignature>() {
                    public boolean areEquals(PGPSignature lhs, PGPSignature rhs) {
                        return signaturesAreEqual(lhs, rhs);
                    }
                }
        )) {
            return false;
        }

        return true;
    }

    public static boolean signaturesAreEqual(PGPSignature a, PGPSignature b) {

        if (a.getVersion() != b.getVersion()) {
            return false;
        }

        if (a.getKeyAlgorithm() != b.getKeyAlgorithm()) {
            return false;
        }

        if (a.getHashAlgorithm() != b.getHashAlgorithm()) {
            return false;
        }

        if (a.getSignatureType() != b.getSignatureType()) {
            return false;
        }

        try {
            if (!Arrays.equals(a.getSignature(), b.getSignature())) {
                return false;
            }
        } catch (PGPException ex) {
            throw new RuntimeException(ex);
        }

        if (a.getKeyID() != b.getKeyID()) {
            return false;
        }

        if (!TestDataUtil.equals(a.getCreationTime(), b.getCreationTime())) {
            return false;
        }

        if (!Arrays.equals(a.getSignatureTrailer(), b.getSignatureTrailer())) {
            return false;
        }

        if (!subPacketVectorsAreEqual(a.getHashedSubPackets(), b.getHashedSubPackets())) {
            return false;
        }

        if (!subPacketVectorsAreEqual(a.getUnhashedSubPackets(), b.getUnhashedSubPackets())) {
            return false;
        }

        return true;
    }

    private static boolean subPacketVectorsAreEqual(PGPSignatureSubpacketVector aHashedSubPackets, PGPSignatureSubpacketVector bHashedSubPackets) {
        for (int i = 0; i < Byte.MAX_VALUE; i++) {
            if (!TestDataUtil.iterEquals(Arrays.asList(aHashedSubPackets.getSubpackets(i)).iterator(),
                    Arrays.asList(bHashedSubPackets.getSubpackets(i)).iterator(),
                    new TestDataUtil.EqualityChecker<SignatureSubpacket>() {
                        @Override
                        public boolean areEquals(SignatureSubpacket lhs, SignatureSubpacket rhs) {
                            return signatureSubpacketsAreEqual(lhs, rhs);
                        }
                    }
            )) {
                return false;
            }

        }
        return true;
    }

    private static boolean signatureSubpacketsAreEqual(SignatureSubpacket lhs, SignatureSubpacket rhs) {
        if (lhs.getType() != rhs.getType()) {
            return false;
        }
        if (!Arrays.equals(lhs.getData(), rhs.getData())) {
            return false;
        }
        return true;
    }

    public static boolean pubKeyPacketsAreEqual(PublicKeyPacket a, PublicKeyPacket b) {

        if (a.getAlgorithm() != b.getAlgorithm()) {
            return false;
        }

        if (!bcpgKeysAreEqual(a.getKey(), b.getKey())) {
            return false;
        }

        if (!TestDataUtil.equals(a.getTime(), b.getTime())) {
            return false;
        }

        if (a.getValidDays() != b.getValidDays()) {
            return false;
        }

        if (a.getVersion() != b.getVersion()) {
            return false;
        }

        return true;
    }

    public static boolean bcpgKeysAreEqual(BCPGKey a, BCPGKey b) {

        if (!TestDataUtil.equals(a.getFormat(), b.getFormat())) {
            return false;
        }

        if (!Arrays.equals(a.getEncoded(), b.getEncoded())) {
            return false;
        }

        return true;
    }


    public void doTestCanonicalize(UncachedKeyRing inputKeyRing, UncachedKeyRing expectedKeyRing) {
        if (!compareRing(inputKeyRing, expectedKeyRing)) {
            throw new AssertionError("Expected [" + inputKeyRing + "] to match [" + expectedKeyRing + "]");
        }
    }

}
