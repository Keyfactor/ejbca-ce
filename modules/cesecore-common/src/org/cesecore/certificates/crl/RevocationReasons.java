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
package org.cesecore.certificates.crl;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An enum for revocation reasons, with a numerical database value and a String value for CLI applications.
 * <p>
 * Based on RFC 5280 Section 5.3.1
 *
 * @version $Id$
 */
public enum RevocationReasons {
    NOT_REVOKED(-1, "NOT_REVOKED", "The Certificate Is Not Revoked"),
    UNSPECIFIED(0, "UNSPECIFIED", "Unspecified"),
    KEYCOMPROMISE(1, "KEY_COMPROMISE", "Key Compromise"),
    CACOMPROMISE(2, "CA_COMPROMISE", "CA Compromise"),
    AFFILIATIONCHANGED(3, "AFFILIATION_CHANGED", "Affiliation Changed"),
    SUPERSEDED(4, "SUPERSEDED", "Superseded"),
    CESSATIONOFOPERATION(5, "CESSATION_OF_OPERATION", "Cessation of Operation"),
    CERTIFICATEHOLD(6, "CERTIFICATE_HOLD", "Certificate Hold"),
    REMOVEFROMCRL(8, "REMOVE_FROM_CRL", "Remove from CRL"),
    PRIVILEGESWITHDRAWN(9, "PRIVILEGES_WITHDRAWN", "Privileges Withdrawn"),
    AACOMPROMISE(10, "AA_COMPROMISE", "AA Compromise");

    private final int databaseValue;
    private final String stringValue;
    private final String humanReadable;

    private static final List<RevocationReasons> reasonableRevocationReasons =
            List.of(RevocationReasons.AFFILIATIONCHANGED,
                    RevocationReasons.CESSATIONOFOPERATION,
                    RevocationReasons.KEYCOMPROMISE,
                    RevocationReasons.PRIVILEGESWITHDRAWN,
                    RevocationReasons.SUPERSEDED,
                    RevocationReasons.UNSPECIFIED
            );


    private RevocationReasons(final int databaseValue, final String stringValue, final String humanReadable) {
        this.databaseValue = databaseValue;
        this.stringValue = stringValue;
        this.humanReadable = humanReadable;
    }

    public int getDatabaseValue() {
        return databaseValue;
    }

    public String getHumanReadable() {
        return humanReadable;
    }

    public String getStringValue() {
        return stringValue;
    }

    /**
     * @param databaseValue the database value
     * @return the relevant RevocationReasons object, null if none found.
     */
    public static RevocationReasons getFromDatabaseValue(int databaseValue) {
        return Arrays.stream(values())
                .filter(item -> item.getDatabaseValue() == databaseValue)
                .findAny().orElse(null);
    }

    /**
     * @param cliValue the database value
     * @return the relevant RevocationReasons object, null if none found.
     */
    public static RevocationReasons getFromCliValue(String cliValue) {
        if (cliValue == null) {
            return null;
        }
        return Arrays.stream(values())
                .filter(item -> item.getStringValue().equals(cliValue))
                .findAny().orElse(null);
    }

    /**
     * Returns the collection of reasonable revocation reason codes.
     * <p>
     * Verify that the revocation reason code is allowed (see https://tools.ietf.org/html/rfc8555#section-7.6)
     * ACME server MAY disallow a subset may of reasonCodes ... defined in RFC5820 ...
     *
     * @return the collection of revocation reason codes.
     */
    public static Collection<Integer> getReasonableRevocationReasonCodes() {
        return reasonableRevocationReasons.stream()
                .map(RevocationReasons::getDatabaseValue)
                .collect(Collectors.toList());
    }
}
