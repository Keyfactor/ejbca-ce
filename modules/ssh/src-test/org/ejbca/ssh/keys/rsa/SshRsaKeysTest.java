/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.keys.rsa;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class SshRsaKeysTest {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testRsaKeysExport() throws IOException {
        SshRsaKeyPair sshRsaKeyPair = new SshRsaKeyPair(1024);
        final String commment = "foo";
        String exportedPublicKey = new String(sshRsaKeyPair.getPublicKey().encodeForExport(commment));
        assertTrue("Exported public key did not contain RSA prefix.", exportedPublicKey.startsWith("ssh-rsa "));
        assertTrue("Exported public key BASE64 did not contain RSA prefix.", exportedPublicKey.contains("AAAAB3NzaC1yc2EA"));
        assertTrue("Exported public key did not end with comment.", exportedPublicKey.endsWith(commment));
    }

}
