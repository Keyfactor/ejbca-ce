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
package org.cesecore.audit.audit;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * A sub-element of a AuditLogValidationReport representing an error or warning.
 * 
 * @version $Id$
 */
public class AuditLogReportElem implements Serializable {

    private static final long serialVersionUID = -7018231147212983227L;
    
    private Long first;
    private Long second;
    private final List<String> reasons = new ArrayList<String>();
    
    public AuditLogReportElem() {
    }
    
    public AuditLogReportElem(final Long first, final Long second, final List<String> reasons) {
    	this.first = first;
    	this.second = second;
    	this.reasons.addAll(reasons);
    }
    
    public AuditLogReportElem(final Long first, final Long second, final String reason) {
    	this.first = first;
    	this.second = second;
    	this.reasons.add(reason);
    }
    
    /**
     * Gets the first for this instance.
     *
     * @return The first.
     */
    public Long getFirst() {
        return this.first;
    }
    /**
     * Sets the first for this instance.
     *
     * @param first The first.
     */
    public void setFirst(Long first) {
        this.first = first;
    }
    /**
     * Gets the second for this instance.
     *
     * @return The second.
     */
    public Long getSecond() {
        return this.second;
    }
    /**
     * Sets the second for this instance.
     *
     * @param second The second.
     */
    public void setSecond(Long second) {
        this.second = second;
    }
    /**
     * Gets the reasons for this instance.
     *
     * @return The reasons.
     */
    public List<String> getReasons() {
        return this.reasons;
    }
    /**
     * Sets the reasons for this instance.
     *
     * @param reasons The reasons.
     */
    public void setReason(String reason) {
        this.reasons.add(reason);
    }

}
