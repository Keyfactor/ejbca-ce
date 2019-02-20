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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.faces.model.SelectItem;

import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Class holding data for active directory publisher used in edit publisher bean.
 * 
 * @version $Id$
 *
 */
public final class ActiveDirectoryPublisherMBData implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private static final Map<Integer, String> AVAILABLE_SAM_ACCOUNTS;
    
    static {
        AVAILABLE_SAM_ACCOUNTS = new LinkedHashMap<>();
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.UPN, "MATCHUPN");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.CN, "MATCHCOMMONNAME");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.UID, "MATCHUID");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.SN, "MATCHDNSERIALNUMBER");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.GIVENNAME, "MATCHGIVENNAME");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.SURNAME, "MATCHSURNAME");
    }
    
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
    
    public List<SelectItem> getAvailableSamAccountNames() {
        List<SelectItem> result = new ArrayList<>();
        for(final int samAccount : AVAILABLE_SAM_ACCOUNTS.keySet()){ 
            result.add(new SelectItem(samAccount, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(AVAILABLE_SAM_ACCOUNTS.get(samAccount))));
        }
        return result;
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
