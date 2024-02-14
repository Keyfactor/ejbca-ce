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

import com.keyfactor.util.StringTools;
import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.protocol.msae.MsaeRaConfigCacheLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

import javax.ejb.EJB;
import javax.enterprise.context.SessionScoped;
import javax.inject.Named;
import java.io.Serializable;
import java.util.List;

/**
 *
 */
@Named
@SessionScoped
public class AutoenrollmentConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    
    @EJB
    private MsaeRaConfigCacheLocal msaeRaConfigCache;

    private String selectedAlias;
    private String newAlias;
    private boolean viewOnly = true;

    public AutoenrollmentConfigMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }

    public List<String> getAutoenrollConfigAliasesSelectItemList() {
        return getEjbcaWebBean().getAutoenrollConfiguration().getSortedAliasList();
    }

    public String addAlias() throws AuthorizationDeniedException {
        selectedAlias = null;
        viewOnly = false;
        return "edit";
    }

    public String cloneAliasAction() throws AuthorizationDeniedException {
        if (StringUtils.isEmpty(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return null;
        }
        if (!StringTools.checkFieldForLegalChars(newAlias)) {
            addErrorMessage("ONLYCHARACTERS");
            return null;
        }
        if (getEjbcaWebBean().getAutoenrollConfiguration().aliasExists(newAlias)) {
            addErrorMessage("ESTCOULDNOTRENAMEORCLONE");
            return null;
        }
        getEjbcaWebBean().cloneAutoenrollAlias(selectedAlias, newAlias);
        newAlias = null;
        selectedAlias = null;
        return "done";
    }

    public String deleteAliasAction() throws AuthorizationDeniedException {
        getEjbcaWebBean().removeAutoenrollAlias(selectedAlias);
        if (getEjbcaWebBean().getAutoenrollConfiguration().aliasExists(selectedAlias)) {
            addErrorMessage("MSAE_COULD_NOT_DELETE_ALIAS");
        } else {
            // Removing alias from MSAE config local cache after it gets delete to invalidate the cache!
            msaeRaConfigCache.removeMsaeAlias(selectedAlias);
        }
        selectedAlias = null;
        return "done";
    }

    public String actionDelete(final String alias) {
        selectedAlias = alias;
        return "delete";
    }

    public String actionClone(final String alias) {
        selectedAlias = alias;
        return "clone";
    }

    public void actionCancel() {
        selectedAlias = null;
        newAlias = null;
    }

    /**
     * @return the navigation outcome defined in faces-config.xml
     */
    public String actionView(final String alias) {
        selectedAlias = alias;
        viewOnly = true;
        return "view";
    }

    /**
     * @return the navigation outcome defined in faces-config.xml
     */
    public String actionEdit(final String alias) {
        selectedAlias = alias;
        viewOnly = false;
        return "edit";
    }

    /**
     * @return true if no aliases have been configured yet
     */
    public boolean isAliasListEmpty() {
        return getEjbcaWebBean().getAutoenrollConfiguration().getSortedAliasList().isEmpty();
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
