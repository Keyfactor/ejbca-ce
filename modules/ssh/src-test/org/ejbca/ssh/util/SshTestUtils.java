/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.util;

import java.util.HashMap;
import java.util.Map;

import org.cesecore.certificates.certificate.ssh.SshCertificate;
import org.cesecore.certificates.certificate.ssh.SshExtension;

/**
 * SSH CA Test utilities.
 *
 * @version $Id$
 */
public class SshTestUtils {

    /**
     * Returns a map of Critical Options with defaults:
     * <ul>
     *     <li>CRITICAL_OPTION_SOURCE_ADDRESS = 127.0.0.1</li>
     * </ul>
     *
     * @return a map of Critical Options with defaults.
     */
    public static Map<String, String> getDefaultCriticalOptionsMap() {
        return getCriticalOptionsMap("127.0.0.1");
    }

    /**
     * Returns a map of Critical Options with CRITICAL_OPTION_SOURCE_ADDRESS = sourceAddress0,sourceAddress1,sourceAddress2...
     *
     * @return a map of Critical Options.
     */
    public static Map<String, String> getCriticalOptionsMap(final String... sourceAddress) {
        final Map<String, String> options = new HashMap<>();
        System.out.println("sourceAddress: [" + String.join(",", sourceAddress) + "]");
        options.put(SshCertificate.CRITICAL_OPTION_SOURCE_ADDRESS, String.join(",", sourceAddress));
        return options;
    }

    /**
     * Returns a map of all SSH Extensions with byte[0].
     *
     * @return a map of all SSH Extensions with byte[0].
     */
    public static Map<String, byte[]> getAllSshExtensionsMap() {
        final Map<String, byte[]> extensions = new HashMap<>();
        for(SshExtension sshExtension : SshExtension.values()) {
            extensions.put(sshExtension.getLabel(), sshExtension.getValue());
        }
        return extensions;
    }

    /**
     * Returns a map of SSH Extensions with byte[0] on top of all extensions with exclusions.
     *
     * @param sshExtensionExclusions Array of extensions to be excluded.
     *
     * @return a map of SSH Extensions with byte[0].
     */
    public static Map<String, byte[]> getSshExtensionsMapWithExclusions(SshExtension ...sshExtensionExclusions) {
        final Map<String, byte[]> extensions = getAllSshExtensionsMap();
        for(SshExtension sshExtension : sshExtensionExclusions) {
            extensions.remove(sshExtension.getLabel());
        }
        return extensions;
    }
}
