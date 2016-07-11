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
 * Contains search parameters for searchForApprovalRequests.
 * 
 * @version $Id$
 */
public class RaRequestsSearchRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private boolean searchingWaitingForMe;
    private boolean searchingPending;
    private boolean searchingHistorical;
    
    
    public boolean isSearchingWaitingForMe() {
        return searchingWaitingForMe;
    }
    
    public void setSearchingWaitingForMe(final boolean searchingWaitingForMe) {
        this.searchingWaitingForMe = searchingWaitingForMe;
    }
    
    public boolean isSearchingPending() {
        return searchingPending;
    }
    
    public void setSearchingPending(final boolean searchingPending) {
        this.searchingPending = searchingPending;
    }
    
    public boolean isSearchingHistorical() {
        return searchingHistorical;
    }
    
    public void setSearchingHistorical(final boolean searchingHistorical) {
        this.searchingHistorical = searchingHistorical;
    }

    // TODO extend with more stuff for custom search (e.g. ECA-5124)

    
}
