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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Represents a return type for publishing operations. Successes and failures are stored in sets containing the fingerprints of what's being stored
 * due to the fact that the publisher will by default retry 20,000 times on a failed attempt, so the "failures" will be per attempted certificate 
 * and not all attempts.
 * 
 * @version $Id$
 *
 */
public class PublishingResult implements Serializable {

    private static final long serialVersionUID = 1L;
    private Set<String> successes;
    private Set<String> failures;
    private Map<String, String> messages;
    
    public PublishingResult() {
        successes = new HashSet<>();
        failures = new HashSet<>();
        messages = new HashMap<>();
    }
    
    public void addSuccess(final String fingerprint) {
        successes.add(fingerprint);
    }
    
    public void addFailure(final String fingerprint) {
        failures.add(fingerprint);
    }
    
    public void addSuccess(final String fingerprint, final String message) {
        successes.add(fingerprint);
        messages.put(fingerprint, message);
    }
    
    public void addFailure(final String fingerprint, final String message) {
        failures.add(fingerprint);
        messages.put(fingerprint, message);
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
    
    /**
     * @param fingerprint of the entry containing a message
     * @return message for the queries entry. May return null.
     */
    public String getMessage(final String fingerprint) {
        return messages.get(fingerprint);
    }
    
    /**
     * @param fingerprint success / failed entry to set message for
     * @param messasge success / error message.
     */
    public void setMessage(final String fingerprint, final String messasge) {
        this.messages.put(fingerprint, messasge);
    }
    
    public void append(PublishingResult result) {
        this.successes.addAll(result.successes);
        this.failures.addAll(result.failures);
    }

}
