/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

/**
 * Utility methods for parsing OIDs used by system configuration beans.
 * 
 * @author Marcus Lundblad
 */
public class OidUtils {
    /**
     * Checks that OID represented in string form consists of only numeric parts.
     * 
     * @param oid String representing an OID
     * @return True if string contains an OID only consisting of numeric parts
     */
    public static boolean isOidNumericalOnly(String oid) {
        final String[] oidParts = oid.split("\\.");

        for (final String oidPart : oidParts) {
            if (oidPart.equals("*")) {
                // Allow wildcard characters
                continue;
            }
            try {
                Integer.parseInt(oidPart);
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }
}
