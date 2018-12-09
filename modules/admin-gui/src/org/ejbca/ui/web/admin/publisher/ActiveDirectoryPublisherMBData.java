package org.ejbca.ui.web.admin.publisher;

public final class ActiveDirectoryPublisherMBData {

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
    
}
