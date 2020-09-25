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

package org.ejbca.ui.web.admin;

import java.io.Serializable;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;

@ManagedBean
@SessionScoped
public class InitPkiMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(InitPkiMBean.class);
    
    private static final String NEW_PKI_MODE = "newPkiMode";
    private static final String EXISTING_PKI_MODE = "existingPkiMode";
    
    private String installationMode;
    
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CaSessionLocal caSession;

    public InitPkiMBean() {
        super(StandardRules.ROLE_ROOT.resource());
    }

    public String getInstallationMode() {
        return StringUtils.isEmpty(installationMode) ? NEW_PKI_MODE : installationMode;
    }

    public void setInstallationMode(String installationMode) {
        this.installationMode = installationMode;
    }
    
    public boolean isInstallExistingPki() {
        return StringUtils.equals(installationMode, EXISTING_PKI_MODE);
    }
    
    public String actionNext() {
        return getInstallationMode();
    }
}
