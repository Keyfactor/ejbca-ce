package org.jscep.util;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * This is a utility class for performing various operations pertaining to X.500
 * objects.
 */
public final class X500Utils {
    private X500Utils() {
    }

    /**
     * Converts a Java SE X500Principal to a Bouncy Castle X500Name.
     * 
     * @param principal
     *            the principal to convert.
     * @return the converted name.
     */
    public static X500Name toX500Name(final X500Principal principal) {
        byte[] bytes = principal.getEncoded();
        return X500Name.getInstance(bytes);
    }
}
