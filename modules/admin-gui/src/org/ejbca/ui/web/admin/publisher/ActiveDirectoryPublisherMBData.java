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
package org.ejbca.ui.web.admin.publisher;

import java.io.Serializable;

import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;

/**
 * Class holding data for active directory publisher used in edit publisher bean.
 * 
 * @version $Id$
 *
 */
public final class ActiveDirectoryPublisherMBData implements Serializable {

    private static final long serialVersionUID = 1L;
    
    public ActiveDirectoryPublisherMBData(final ActiveDirectoryPublisher activeDirectoryPublisher) {
        initializeData(activeDirectoryPublisher);
    }

    private int samAccountName;
    private String userDescription;

    
    public String getUserDescription() {
        return userDescription;
    }

    public void setUserDescription(final String userDescription) {
        this.userDescription = userDescription;
    }
    
    public int getSamAccountName() {
        return samAccountName;
    }

    public void setSamAccountName(final int samAccountName) {
        this.samAccountName = samAccountName;
    }

    public void setActiveDirectoryPublisherParameters(final ActiveDirectoryPublisher activeDirectoryPublisher) {
        activeDirectoryPublisher.setSAMAccountName(samAccountName);
        activeDirectoryPublisher.setUserDescription(userDescription);
    }
    
    private void initializeData(final ActiveDirectoryPublisher publisher) {
        this.userDescription = publisher.getUserDescription();
        this.samAccountName = publisher.getSAMAccountName();
    }
}
