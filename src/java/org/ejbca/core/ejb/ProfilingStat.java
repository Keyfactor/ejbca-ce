/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb;

import java.io.Serializable;

/**
 * Aggregated statistics about an EJB method invocation.
 * 
 * @version $Id$
 */
public class ProfilingStat implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private final String fullmethodName;
    private final long duration;
    private final long invocations;
    private final long average;
    
    public ProfilingStat(final String fullmethodName, final long duration, final long invocations) {
        this.fullmethodName = fullmethodName;
        this.duration = duration;
        this.invocations = invocations;
        this.average = duration/invocations;
    }

    public String getFullmethodName() { return fullmethodName; }
    public long getDurationMicroSeconds() { return duration; }
    public long getDurationMilliSeconds() { return duration/1000; }
    public long getInvocations() { return invocations; }
    public long getAverageMicroSeconds() { return average; }
    public long getAverageMilliSeconds() { return average/1000; }
}
