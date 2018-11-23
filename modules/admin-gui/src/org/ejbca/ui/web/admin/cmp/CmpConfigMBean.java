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

package org.ejbca.ui.web.admin.cmp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJB;
import javax.faces.context.FacesContext;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.util.StringTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JavaServer Faces Managed Bean for managing CMP configuration.
 * @version $Id$
 *
 */
//@ManagedBean
//@SessionScoped
public class CmpConfigMBean extends BaseManagedBean implements Serializable {

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CmpConfigMBean.class);

    private String selectedCmpAlias;
    private String newCmpAlias = "";
    // Indicates a delete action in progress to render its view
    private boolean deleteInProgress = false;
    private boolean viewOnly = true;
    
    
    // Authentication check and audit log page access request
    public void initialize(ComponentSystemEvent event) throws Exception {
        // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
        }
    }
    
    public CmpConfiguration getCmpConfig() {
        return (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }
    
    public List<SelectItem> getCmpAliasSeletItems() {
        final List<String> aliases = getCmpConfig().getSortedAliasList();
        final List<SelectItem> selectItems = new ArrayList<>();
        for (String alias : aliases) {
            selectItems.add(new SelectItem(alias));
        }
        return selectItems;
    }
    
    
    /* Actions */
    
    // Many of the following validations are redundant in CmpConfiguration. However,
    // we need them to display proper error messages
    public void addCmpAlias() {
        if (StringUtils.isNotEmpty(newCmpAlias.trim())) {
            if (!StringTools.checkFieldForLegalChars(newCmpAlias)) {
                addErrorMessage("ONLYCHARACTERS");
            } else if (getCmpConfig().aliasExists(newCmpAlias.trim())) {
                addErrorMessage("CMPALIASEXISTS");
            } else {
                getCmpConfig().addAlias(newCmpAlias.trim());
                newCmpAlias = null;
            }
        }
    }

    public void renameCmpAlias() {
        if (selectedCmpAlias != null && newCmpAlias != null) {
            newCmpAlias = newCmpAlias.trim();
            if (StringUtils.isNotEmpty(newCmpAlias) && StringUtils.isNotEmpty(selectedCmpAlias)) {
                if (!StringTools.checkFieldForLegalChars(newCmpAlias)) {
                    addErrorMessage("ONLYCHARACTERS");
                } else if (getCmpConfig().aliasExists(newCmpAlias)) {
                    addErrorMessage("CMPALIASEXISTS");
                } else {
                    getCmpConfig().renameAlias(selectedCmpAlias, newCmpAlias);
                    newCmpAlias = null;
                }
            }
        }
    }

    public void cloneCmpAlias() {
        if (selectedCmpAlias != null && newCmpAlias != null) {
            newCmpAlias = newCmpAlias.trim();
            if (StringUtils.isNotEmpty(newCmpAlias) && StringUtils.isNotEmpty(selectedCmpAlias)) {
                if (!StringTools.checkFieldForLegalChars(newCmpAlias)) {
                    addErrorMessage("ONLYCHARACTERS");
                } else if(getCmpConfig().aliasExists(newCmpAlias)) {
                    addErrorMessage("CMPALIASEXISTS");
                } else {
                    getCmpConfig().cloneAlias(selectedCmpAlias, newCmpAlias);
                    newCmpAlias = null;
                }
            }
        }
    }

    public void deleteCmpAlias() {
        if (StringUtils.isNotEmpty(selectedCmpAlias)) {
            getCmpConfig().removeAlias(selectedCmpAlias);
        }
        actionCancel();
    }
    
    /** @return the navigation outcome defined in faces-config.xml */
    public String actionEdit() {
        if (StringUtils.isNotEmpty(selectedCmpAlias)) {
            viewOnly = false;
            return "edit";
        }
        addErrorMessage("CMPNOTSELECTED");
        return "";
    }
    
    /** @return the navigation outcome defined in faces-config.xml */
    public String actionView() {
        if (StringUtils.isNotEmpty(selectedCmpAlias)) {
            viewOnly = true;
            return "view";
        }
        addErrorMessage("CMPNOTSELECTED");
        return "";
    }
    
    public void actionDelete() {
        if (StringUtils.isNotEmpty(selectedCmpAlias)) {
            deleteInProgress = true;
        } else {
            addErrorMessage("CMPNOTSELECTED");
        }
    }

    public void actionCancel() {
        deleteInProgress = false;
        selectedCmpAlias = null;
        newCmpAlias = null;
    }
    
    
    /* Getters & Setters */
    
    public String getSelectedCmpAlias() { return selectedCmpAlias; }
    public void setSelectedCmpAlias(String selectedCmpAlias) { this.selectedCmpAlias = selectedCmpAlias; }
    
    public String getNewCmpAlias() { return newCmpAlias; }
    public void setNewCmpAlias(String newCmpAlias) { this.newCmpAlias = newCmpAlias;}
    
    /* Rendering Conditions */
    
    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }
    
    public boolean isAuthorizedToEdit() {
        return isAuthorizedTo(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }
    
    public boolean isViewOnly() {
        return viewOnly;
    }
}
