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
package org.ejbca.core.model.era;

import java.io.Serializable;

/**
 * @version $Id$
 */
public class RaCrlSearchRequest implements Serializable {
    private static final long serialVersionUID = 1L;

    private String caName;
    private String issuerDn;
    private boolean deltaCRL;
    private int crlPartitionIndex;

    public String getCaName() {
        return caName;
    }

    public void setCaName(String caName) {
        this.caName = caName;
    }

    public String getIssuerDn() {
        return issuerDn;
    }

    public void setIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
    }

    public boolean isDeltaCRL() {
        return deltaCRL;
    }

    public void setDeltaCRL(boolean deltaCRL) {
        this.deltaCRL = deltaCRL;
    }

    public int getCrlPartitionIndex() {
        return crlPartitionIndex;
    }

    public void setCrlPartitionIndex(int crlPartitionIndex) {
        this.crlPartitionIndex = crlPartitionIndex;
    }
}
