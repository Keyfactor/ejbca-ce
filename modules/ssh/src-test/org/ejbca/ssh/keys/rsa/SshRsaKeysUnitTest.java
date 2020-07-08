/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.keys.rsa;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * SSH RSA Keys tests.
 *
 * @version $Id$
 */
public class SshRsaKeysUnitTest {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void rsaKeysExport() throws IOException {
        SshRsaKeyPair sshRsaKeyPair = new SshRsaKeyPair(1024);
        final String comment = "foo";
        String exportedPublicKey = new String(sshRsaKeyPair.getPublicKey().encodeForExport(comment));
        assertTrue("Exported public key did not contain RSA prefix.", exportedPublicKey.startsWith("ssh-rsa "));
        assertTrue("Exported public key BASE64 did not contain RSA prefix.", exportedPublicKey.contains("AAAAB3NzaC1yc2EA"));
        assertTrue("Exported public key did not end with comment.", exportedPublicKey.endsWith(comment));
    }

}
