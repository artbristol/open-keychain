package org.sufficientlysecure.keychain.testsupport;

import org.spongycastle.bcpg.BCPGKey;
import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.bcpg.PublicKeyPacket;
import org.spongycastle.bcpg.RSAPublicBCPGKey;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSignature;
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

    public static UncachedKeyRing ring1() {
        BigInteger modulus = BigInteger.ONE;
        return ringForModulus(modulus, new Date());
    }

    public static UncachedKeyRing ring2() {
        BigInteger modulus = BigInteger.ONE;
        return ringForModulus(modulus, new Date());
    }

    private static UncachedKeyRing ringForModulus(BigInteger modulus, Date date) {
        BigInteger exponent = BigInteger.valueOf(65537);
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

//        public PGPSignatureSubpacketVector getHashedSubPackets()
//        public PGPSignatureSubpacketVector getUnhashedSubPackets()

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
