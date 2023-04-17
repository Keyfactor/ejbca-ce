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
import javax.enterprise.context.SessionScoped;
import javax.faces.model.SelectItem;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

import com.keyfactor.util.StringTools;

/**
 * JavaServer Faces Managed Bean for managing CMP configuration.
 *
 */
@Named
@SessionScoped
public class CmpConfigMBean extends BaseManagedBean implements Serializable {

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    
    private static final long serialVersionUID = 1L;

    private String selectedCmpAlias;
    private String newCmpAlias = "";
    // Indicates a delete action in progress to render its view
    private boolean deleteInProgress = false;
    private boolean viewOnly = true;
    
    public CmpConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }
    
    public CmpConfiguration getCmpConfig() {
        return (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }
    
    public List<SelectItem> getCmpAliasSelectItems() {
        final List<String> aliases = getCmpConfig().getSortedAliasList();
        final List<SelectItem> selectItems = new ArrayList<>();
        aliases.forEach(alias -> selectItems.add(new SelectItem(alias)));
        return selectItems;
    }
    
    /* Actions */
    
    public void addCmpAlias() throws AuthorizationDeniedException {
        if (validateNewAlias()) {
            getEjbcaWebBean().addCmpAlias(newCmpAlias);
            newCmpAlias = null;
        }
    }

    public void renameCmpAlias() throws AuthorizationDeniedException {
        if (StringUtils.isEmpty(selectedCmpAlias)) {
            addErrorMessage("CMPNOTSELECTED");
        } else if (validateNewAlias()) {
            getEjbcaWebBean().renameCmpAlias(selectedCmpAlias, newCmpAlias);
            newCmpAlias = null;
        }
    }

    public void cloneCmpAlias() throws AuthorizationDeniedException {
        if (StringUtils.isEmpty(selectedCmpAlias)) {
            addErrorMessage("CMPNOTSELECTED");
        } else if (validateNewAlias()) {
            getEjbcaWebBean().cloneCmpAlias(selectedCmpAlias, newCmpAlias);
            newCmpAlias = null;
        } 
    }

    /**
     * @return false if new alias already exists or contains illegal characters
     */
    private boolean validateNewAlias() {
        // Following validations are redundant in CmpConfiguration. However,
        // we need them to display proper error messages
        newCmpAlias = newCmpAlias.trim();
        if (StringUtils.isEmpty(newCmpAlias) || !StringTools.checkFieldForLegalChars(newCmpAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return false;
        } else if(getCmpConfig().aliasExists(newCmpAlias)) {
            addErrorMessage("CMPALIASEXISTS");
            return false;
        }
        return true;
    }
    
    public void deleteCmpAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(selectedCmpAlias)) {
            getEjbcaWebBean().removeCmpAlias(selectedCmpAlias);
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
