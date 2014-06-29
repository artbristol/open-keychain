package tests;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.*;
import org.sufficientlysecure.keychain.testsupport.UncachedKeyringTestingHelper;

@RunWith(RobolectricTestRunner.class)
@org.robolectric.annotation.Config(emulateSdk = 18) // Robolectric doesn't yet support 19
public class UncachedKeyringTest {

    @Test
    public void testVerifySuccess() throws Exception {
        new UncachedKeyringTestingHelper().doTestCanonicalize(
                UncachedKeyringTestingHelper.ring1(), UncachedKeyringTestingHelper.ring2());
    }


}
