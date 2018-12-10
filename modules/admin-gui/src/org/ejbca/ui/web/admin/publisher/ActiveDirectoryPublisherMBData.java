package org.ejbca.ui.web.admin.publisher;

import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;

public final class ActiveDirectoryPublisherMBData extends LdapPublisherMBData {

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
    
    public ActiveDirectoryPublisher getPublisherInstance(final ActiveDirectoryPublisher publisher) {
        publisher.setSAMAccountName(samAccountName);
        publisher.setUserDescription(userDescription);
        return publisher;
    }
    
    public void initializeData(final ActiveDirectoryPublisher publisher) {
        super.initializeData(publisher);
        this.userDescription = publisher.getUserDescription();
        this.samAccountName = publisher.getSAMAccountName();
    }
    
}
