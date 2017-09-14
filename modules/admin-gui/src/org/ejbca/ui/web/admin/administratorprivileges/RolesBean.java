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
package org.ejbca.ui.web.admin.administratorprivileges;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.RaCssInfo;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionLocal;
import org.ejbca.config.GlobalCustomCssConfiguration;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Managed Bean for the Roles overview page.
 * 
 * @version $Id$
 */
@ViewScoped
@ManagedBean
public class RolesBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(RolesBean.class);
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    
    private boolean addRoleInProgress = false;
    private Role roleToRename = null;
    private Role roleToDelete = null;
    private String editNameSpaceSelected;
    private String editNameSpace;
    private String editRoleName;
    private int selectedCss;
    private List<SelectItem> raCssList;
    private ListDataModel<Role> rolesAvailable;
    private List<String> nameSpacesAvailable;
    private boolean onlyEmptyNameSpaceInUse = true;

    @PostConstruct
    private void postConstruct() {
        reloadRolesAndNameSpaces();
        editReset();
    }

    /** @return true when admin is authorized to view roles */
    public boolean isAuthorizedToViewRoles() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.VIEWROLES.resource());
    }

    /** @return true when admin is authorized to edit roles (which implies view rights) */
    public boolean isAuthorizedToEditRoles() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EDITROLES.resource());
    }
    
    /** @return true if the only the empty namespace currently exists on this system */
    public boolean isOnlyEmptyNameSpaceInUse() {
        return onlyEmptyNameSpaceInUse;
    }

    /** @return the ListDataModel of all roles the admin is authorized to */
    public ListDataModel<Role> getRolesAvailable() {
        if (rolesAvailable==null) {
            final List<Role> roles = roleSession.getAuthorizedRoles(super.getAdmin());
            boolean onlyEmptyNameSpaceInUse = true;
            for (final Role role : roles) {
                if (!role.getNameSpace().isEmpty()) {
                    onlyEmptyNameSpaceInUse = false;
                    break;
                }
            }
            this.onlyEmptyNameSpaceInUse = onlyEmptyNameSpaceInUse;
            Collections.sort(roles);
            rolesAvailable = new ListDataModel<>(roles);
        }
        return rolesAvailable;
    }

    /** Trigger a reload of Roles and available namespaces on next request */
    private void reloadRolesAndNameSpaces() {
        nameSpacesAvailable = null;
        rolesAvailable = null;
    }
    
    /** @return true if the admin has access to the empty namespace (and hence is allowed to create new ones) */
    public boolean isAuthorizedToCreateNewNameSpace() {
        return isAuthorizedToEditRoles() && getNameSpaceAvailable().contains("");
    }

    /** @return a list of existing and authorized namespaces that the admin has access to */
    public List<String> getNameSpaceAvailable() {
        if (nameSpacesAvailable==null) {
            nameSpacesAvailable = new LinkedList<>(roleSession.getAuthorizedNamespaces(getAdmin()));
            Collections.sort(nameSpacesAvailable);
        }
        return nameSpacesAvailable;
    }

    /** Invoked while adding or renaming a role to create a new namespace, instead of using one of the existing ones */
    public void actionEditNewNameSpace() {
        // Use the current selected one for convenience, if it's not selected any namespace however, we set it to something so we can edit it.
        // otherwise the isRenderEditNameSpace will not trigger a possibility to edit
        if (StringUtils.isEmpty(editNameSpaceSelected)) {
            editNameSpace = "";
        } else {
            editNameSpace = editNameSpaceSelected;
        }
    }
    
    /** @return true when creating a new namespace, instead of using on of the existing ones while adding or renaming a role */
    public boolean isRenderEditNameSpace() {
        return editNameSpace != null;
    }

    /** @return the currently selected namespace when adding or renaming a role */
    public String getEditNameSpaceSelected() { return editNameSpaceSelected; }
    /** Set the currently selected namespace when adding or renaming a role */
    public void setEditNameSpaceSelected(String editNameSpaceSelected) { this.editNameSpaceSelected = editNameSpaceSelected; }

    /** @return the currently free-text namespace when adding or renaming a role (or null if no free text editing is currently ongoing) */
    public String getEditNameSpace() { return editNameSpace; }
    /** Set the currently free-text namespace when adding or renaming a role (or null if no free text editing is currently ongoing) */
    public void setEditNameSpace(String editNameSpace) { this.editNameSpace = editNameSpace.trim(); }

    /** @return the free-text role name when adding or renaming a role */
    public String getEditRoleName() { return editRoleName; }
    /** Set the free-text role name when adding or renaming a role */
    public void setEditRoleName(String editRoleName) { this.editRoleName = editRoleName.trim(); }
    
    public int getSelectedCss() {
        Role roleToSelect = rolesAvailable.getRowData();
        selectedCss = roleToSelect.getCssId();
        return selectedCss;
    }
    
    public void setSelectedCss(int selectedCss) {
        this.selectedCss = selectedCss;
        saveCss();
    }
    
    public boolean isCssSelectable() {
        boolean authorizedToCssArchives = authorizationSession.isAuthorizedNoLogging(getAdmin(), 
                StandardRules.SYSTEMCONFIGURATION_VIEW.resource(), StandardRules.EDITROLES.resource(), StandardRules.VIEWROLES.resource());
        if (authorizedToCssArchives && raCssList != null && raCssList.size() > 1) {
            return true;
        }
        return false;
    }
    
    public List<SelectItem> getAvailableCssList() throws AuthorizationDeniedException {
        GlobalCustomCssConfiguration globalCustomCssConfiguration = (GlobalCustomCssConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalCustomCssConfiguration.CSS_CONFIGURATION_ID);
        raCssList = new ArrayList<>();
        raCssList.add(new SelectItem(0, "Default"));
        for (RaCssInfo raCssInfo : globalCustomCssConfiguration.getRaCssInfo().values()) {
            raCssList.add(new SelectItem(raCssInfo.getCssId(), raCssInfo.getFileName()));
        }
        return raCssList;
    }
    
    private void saveCss() {
        Role roleToSave = rolesAvailable.getRowData();
        log.info("Role To save: " + roleToSave.getRoleName() + " setting css: " + selectedCss);
        roleToSave.setCssId(selectedCss);
        try {
            roleSession.persistRole(getAdmin(), roleToSave);
        } catch (RoleExistsException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLEEXISTS");
        } catch (AuthorizationDeniedException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLES_ERROR_UNAUTHORIZED", e.getMessage());
        }
    }
    
    private void editReset() {
        editNameSpaceSelected = "";
        editNameSpace = null;
        editRoleName = "";
    }

    /** @return true when the admin is in process of adding a new role */
    public boolean isRenderAddRole() {
        return isAuthorizedToEditRoles() && addRoleInProgress;
    }
    /** Invoked when starting process to add a new role */
    public void actionAddRoleStart() {
        addRoleInProgress = true;
        editNameSpaceSelected = getNameSpaceAvailable().get(0);
    }
    /** Invoked when canceling process to add a new role */
    public void actionAddRoleReset() {
        editReset();
        addRoleInProgress = false;
    }
    /** Invoked when confirming process to add a new role */
    public void actionAddRoleConfirm() {
        if (StringUtils.isEmpty(editRoleName)) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLES_ERROR_EMPTYNAME");
            return;
        }
        try {
            if (editNameSpace==null) {
                editNameSpace = editNameSpaceSelected;
            }
            final Role role = new Role(editNameSpace, editRoleName);
            roleSession.persistRole(getAdmin(), role);
            reloadRolesAndNameSpaces();
            actionAddRoleReset();
            super.addGlobalMessage(FacesMessage.SEVERITY_INFO, "ROLES_INFO_ROLEADDED");
        } catch (RoleExistsException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLEEXISTS");
        } catch (AuthorizationDeniedException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLES_ERROR_UNAUTHORIZED", e.getMessage());
        }
    }
    
    /** @return true when the admin is in process of renaming a role */
    public boolean isRenderRenameRole() {
        return isAuthorizedToEditRoles() && roleToRename!=null;
    }
    /** Invoked when starting process to rename a role */
    public void actionRenameRoleStart() {
        roleToRename = rolesAvailable.getRowData();
        setEditNameSpaceSelected(roleToRename.getNameSpace());
        setEditRoleName(roleToRename.getRoleName());
    }
    /** Invoked when canceling process to rename a role */
    public void actionRenameRoleReset() {
        editReset();
        roleToRename = null;
    }
    /** Invoked when confirming process to rename a role */
    public void actionRenameRoleConfirm() {
        if (StringUtils.isEmpty(editRoleName)) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLES_ERROR_EMPTYNAME");
        }
        try {
            if (editNameSpace==null) {
                editNameSpace = editNameSpaceSelected;
            }
            roleToRename.setNameSpace(editNameSpace);
            roleToRename.setRoleName(editRoleName);
            roleSession.persistRole(getAdmin(), roleToRename);
            actionRenameRoleReset();
            reloadRolesAndNameSpaces();
            super.addGlobalMessage(FacesMessage.SEVERITY_INFO, "ROLES_INFO_RENAMED");
        } catch (RoleExistsException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLEEXISTS");
        } catch (AuthorizationDeniedException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLES_ERROR_UNAUTHORIZED", e.getMessage());
        }
        super.nonAjaxPostRedirectGet(null);
    }

    /** @return true when the admin is in process of deleting a new role */
    public boolean isRenderDeleteRole() {
        return isAuthorizedToEditRoles() && roleToDelete!=null;
    }
    /** @return the role that is the admin has started the process of deleting */
    public Role getRoleToDelete() {
        return roleToDelete;
    }
    /** Invoked when starting process to delete a role */
    public void actionDeleteRoleStart() {
        roleToDelete = rolesAvailable.getRowData();
    }
    /** Invoked when canceling process to delete a role */
    public void actionDeleteRoleReset() {
        roleToDelete = null;
    }
    /** Invoked when confirming process to delete a role */
    public void actionDeleteRoleConfirm() {
        try {
            if (roleSession.deleteRoleIdempotent(getAdmin(), roleToDelete.getRoleId())) {
                super.addGlobalMessage(FacesMessage.SEVERITY_INFO, "ROLES_INFO_DELETED");
            }
        } catch (AuthorizationDeniedException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLES_ERROR_UNAUTHORIZED", e.getMessage());
        }
        actionDeleteRoleReset();
        reloadRolesAndNameSpaces();
        super.nonAjaxPostRedirectGet(null);
    }
}
