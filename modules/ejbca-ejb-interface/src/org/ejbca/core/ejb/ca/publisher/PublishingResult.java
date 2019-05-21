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
package org.ejbca.core.ejb.ca.publisher;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * Represents a return type for publishing operations. Successes and failures are stored in sets containing the fingerprints of what's being stored
 * due to the fact that the publisher 
 * 
 * @version $Id$
 *
 */
public class PublishingResult implements Serializable {

    private static final long serialVersionUID = 1L;
    private Set<String> successes;
    private Set<String> failures;

    public PublishingResult() {
        successes = new HashSet<>();
        failures = new HashSet<>();
    }
    
    public void addSuccess(final String fingerprint) {
        successes.add(fingerprint);
    }
    
    public void addFailure(final String fingerprint) {
        failures.add(fingerprint);
    }
    
    /**
     * @return true if ten failed attempts have been made without any successes.
     */
    public boolean shouldBreakPublishingOperation() {
        return (successes.size() == 0) && (failures.size() > 10);
    }
    
    public int getSuccesses() {
        return successes.size();
    }

    public int getFailures() {
        return failures.size();
    }
    
    public void append(PublishingResult result) {
        this.successes.addAll(result.successes);
        this.failures.addAll(result.failures);
    }

}
