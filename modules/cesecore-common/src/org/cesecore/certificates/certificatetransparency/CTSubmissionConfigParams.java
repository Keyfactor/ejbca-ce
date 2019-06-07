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
package org.cesecore.certificates.certificatetransparency;

import java.io.Serializable;
import java.util.Map;

/**
 * Generic configuration parameters for the {@link CertificateTransparency#fetchSCTList} methods,
 * that are not specific to the certificate profiles.
 * @version $Id$
 */
public final class CTSubmissionConfigParams implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private Map<Integer,CTLogInfo> configuredCTLogs;
    private GoogleCtPolicy validityPolicy;
    
    /**
     * Contains definitions (URL, public key, etc.) of the logs that can be used.
     */
    public Map<Integer, CTLogInfo> getConfiguredCTLogs() {
        return configuredCTLogs;
    }
    
    /**
     * @see #getConfiguredCTLogs
     */
    public void setConfiguredCTLogs(final Map<Integer, CTLogInfo> configuredCTLogs) {
        this.configuredCTLogs = configuredCTLogs;
    }
    
    /**
     * Policy for setting min/max SCTs based on the validity
     */
    public GoogleCtPolicy getValidityPolicy() {
        return validityPolicy;
    }
    
    /**
     * @see #getValidityPolicy
     */
    public void setValidityPolicy(final GoogleCtPolicy validityPolicy) {
        this.validityPolicy = validityPolicy;
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof CTSubmissionConfigParams)) {
            return false;
        }
        final CTSubmissionConfigParams other = (CTSubmissionConfigParams) obj;
        return configuredCTLogs.equals(other.configuredCTLogs) &&
                validityPolicy.equals(other.validityPolicy);
    }

    @Override
    public int hashCode() {
        // We use a sum of the fields hashcodes. The second hashcode is multiplied by some prime number. This is common practice in Java (see String.hashCode)
        return configuredCTLogs.hashCode() + 29*validityPolicy.hashCode();
    }

    @Override
    public String toString() {
        return "CTSubmissionConfigParams{logs=" + configuredCTLogs + ", validity=" + validityPolicy + "}";
    }
}
