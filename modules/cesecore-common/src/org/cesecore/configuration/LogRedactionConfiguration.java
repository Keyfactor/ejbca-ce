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
package org.cesecore.configuration;

// To allow future expansion
public class LogRedactionConfiguration {
    
    private boolean redactPii;

    public LogRedactionConfiguration(boolean redactPii) {
        this.redactPii = redactPii;
    }

    public boolean isRedactPii() {
        return redactPii;
    }

    @Override
    public String toString() {
        return "LogRedactionConfiguration [redactPii=" + redactPii + "]";
    }
    
}
