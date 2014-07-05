package tests;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.*;
import org.sufficientlysecure.keychain.pgp.UncachedKeyRing;
import org.sufficientlysecure.keychain.testsupport.UncachedKeyringTestingHelper;

@RunWith(RobolectricTestRunner.class)
@org.robolectric.annotation.Config(emulateSdk = 18) // Robolectric doesn't yet support 19
public class UncachedKeyringTest {

    @Test
    public void testVerifySuccess() throws Exception {
        UncachedKeyRing expectedKeyRing = UncachedKeyringTestingHelper.ring2();
//        Uncomment to prove it's working - the createdDate will then be different
//        Thread.sleep(1500);
        UncachedKeyRing inputKeyRing = UncachedKeyringTestingHelper.ring1();
        new UncachedKeyringTestingHelper().doTestCanonicalize(
                inputKeyRing, expectedKeyRing);
    }


}
