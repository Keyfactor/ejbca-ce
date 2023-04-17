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
package org.ejbca.ui.web.admin.configuration;

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
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

import com.keyfactor.util.StringTools;

/**
 */
@Named
@SessionScoped
public class EstConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    
    @EJB
    private GlobalConfigurationSessionLocal globalConfigSession;

    private String selectedAlias;
    private String newAlias;
    private boolean viewOnly = true;

    /**
     * Indicates a delete action in progress to render its view.
     */
    private boolean deleteInProgress = false;

    public EstConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }
    
    public EstConfiguration getEstConfiguration() {
        getEjbcaWebBean().reloadEstConfiguration();
        return (EstConfiguration) globalConfigSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
    } 

    public List<SelectItem> getEstConfigAliasesSeletItemList() {
        List<String> aliasList = getEstConfiguration().getSortedAliasList();
        final List<SelectItem> ret = new ArrayList<>();
        for (String alias : aliasList) {
            ret.add(new SelectItem(alias));
        }
        return ret;
    }

    public void addAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(newAlias)) {
            if (!StringTools.checkFieldForLegalChars(newAlias)) {
                addErrorMessage("ONLYCHARACTERS");
            } else {
                if (getEstConfiguration().aliasExists(newAlias)) {
                    addErrorMessage("ESTALIASEXISTS");
                } else {
                    getEjbcaWebBean().addEstAlias(newAlias);
                    newAlias = null;
                }
            }
        }
    }

    public void renameAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(newAlias) && StringUtils.isNotEmpty(selectedAlias)) {
            if (!StringTools.checkFieldForLegalChars(newAlias)) {
                addErrorMessage("ONLYCHARACTERS");
            } else {
                if (getEstConfiguration().aliasExists(newAlias)) {
                    addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
                } else {
                    getEjbcaWebBean().renameEstAlias(selectedAlias, newAlias);
                    newAlias = null;
                }
            }
        }

    }

    public void cloneAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(newAlias) && StringUtils.isNotEmpty(selectedAlias)) {
            if (!StringTools.checkFieldForLegalChars(newAlias)) {
                addErrorMessage("ONLYCHARACTERS");
            } else {
                if (getEstConfiguration().aliasExists(newAlias)) {
                    addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
                } else {
                    getEjbcaWebBean().cloneEstAlias(selectedAlias, newAlias);
                    newAlias = null;
                }
            }
        }
    }

    public void deleteEstAlias() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(selectedAlias)) {
            getEjbcaWebBean().removeEstAlias(selectedAlias);
            if (getEstConfiguration().aliasExists(selectedAlias)) {
                addErrorMessage("ESTCOULDNOTDELETEALIAS");
            }
        }
        actionCancel();
    }

    /**
     * Delete action.
     */
    public void actionDelete() {
        if (StringUtils.isNotEmpty(selectedAlias)) {
            deleteInProgress = true;
        } else {
            addErrorMessage("ESTNOTSELECTED");
        }
    }

    /**
     * Cancel action.
     */
    public void actionCancel() {
        deleteInProgress = false;
        selectedAlias = null;
        newAlias = null;
    }

    /** @return the navigation outcome defined in faces-config.xml */
    public String actionView() {
        if (StringUtils.isNotEmpty(selectedAlias)) {
            viewOnly = true;
            return "view";
        }
        addErrorMessage("ESTNOTSELECTED");
        return "";
    }

    /** @return the navigation outcome defined in faces-config.xml */
    public String actionEdit() {
        if (StringUtils.isNotEmpty(selectedAlias)) {
            viewOnly = false;
            return "edit";
        }
        addErrorMessage("ESTNOTSELECTED");
        return "";
    }

    public boolean isAuthorizedToEdit() {
        return isAuthorizedTo(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }

    public String getSelectedAlias() {
        return selectedAlias;
    }

    public void setSelectedAlias(String selectedAlias) {
        this.selectedAlias = selectedAlias;
    }

    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }

    public String getNewAlias() {
        return newAlias;
    }

    public void setNewAlias(String newAlias) {
        this.newAlias = newAlias.trim();
    }

    public boolean isViewOnly() {
        return viewOnly;
    }
}
