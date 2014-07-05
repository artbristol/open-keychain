package org.sufficientlysecure.keychain.testsupport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Iterator;

/**
 * Misc support functions. Would just use Guava / Apache Commons but
 * avoiding extra dependencies.
 */
public class TestDataUtil {
    public static byte[] readFully(InputStream input) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        appendToOutput(input, output);
        return output.toByteArray();
    }

    private static void appendToOutput(InputStream input, ByteArrayOutputStream output) {
        byte[] buffer = new byte[8192];
        int bytesRead;
        try {
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] readAllFully(Collection<String> inputResources) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        for (String inputResource : inputResources) {
            appendToOutput(getResourceAsStream(inputResource), output);
        }
        return output.toByteArray();
    }

    public static InputStream getResourceAsStream(String resourceName) {
        return TestDataUtil.class.getResourceAsStream(resourceName);
    }

    /**
     * Null-safe equivalent of {@code a.equals(b)}.
     */
    public static boolean equals(Object a, Object b) {
        return (a == null) ? (b == null) : a.equals(b);
    }

    public static <T> boolean iterEquals(Iterator<T> a, Iterator<T> b, EqualityChecker<T> comparator) {
        while (a.hasNext()) {
            T aObject = a.next();
            if (!b.hasNext()) {
                return false;
            }
            T bObject = b.next();
            if (!comparator.areEquals(aObject, bObject) ) {
                return false;
            }
        }

        if (b.hasNext()) {
            return false;
        }

        return true;
    }


    public static <T> boolean iterEquals(Iterator<T> a, Iterator<T> b) {
        return iterEquals(a, b, new EqualityChecker<T>() {
            @Override
            public boolean areEquals(T lhs, T rhs) {
                return TestDataUtil.equals(lhs, rhs);
            }
        });
    }

    public static interface EqualityChecker<T> {
        public boolean areEquals(T lhs, T rhs);
    }

}
