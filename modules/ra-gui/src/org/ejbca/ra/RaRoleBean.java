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
package org.ejbca.ra;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ra.jsfext.AddRemoveListState;


/**
 * Backing bean for the Edit Role page
 *
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaRoleBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaRoleBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAccessBean}")
    private RaAccessBean raAccessBean;
    public void setRaAccessBean(final RaAccessBean raAccessBean) { this.raAccessBean = raAccessBean; }

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    @ManagedProperty(value="#{raRolesBean}")
    private RaRolesBean raRolesBean;
    public void setRaRolesBean(final RaRolesBean raRolesBean) { this.raRolesBean = raRolesBean; }

    private static final Object NEW_NAMESPACE_ITEM = "#NEW#";

    private boolean initialized = false;
    
    private Integer roleId;
    private Integer cloneFromRoleId;
    private Role role;

    private String name;
    private String namespace;
    private String newNamespace;
    private boolean hasAccessToEmptyNamespace;
    private List<String> namespaces;
    private List<SelectItem> namespaceOptions = new ArrayList<>();

    private AddRemoveListState<String> caListState = new AddRemoveListState<>();
    /*private List<RuleSectionGuiInfo> ruleSections;

    public final class RuleSectionGuiInfo implements Serializable {
        private static final long serialVersionUID = 1L;

        private final String header, accessRule;
        private boolean allowed;
        private final List<RuleSectionGuiInfo> rules = new ArrayList<>();
        private final List<RuleSectionGuiInfo> objectRules = new ArrayList<>();

        public RuleSectionGuiInfo(final String header) {
            this.header = header;
            this.accessRule = null;
        }

        public RuleSectionGuiInfo(final String header, final String accessRule) {
            this.header = header;
            this.accessRule = accessRule;
            allowed = AccessRulesHelper.hasAccessToResource(role.getAccessRules(), accessRule);
        }

        public boolean getAllowed() {
            return allowed;
        }

        public void setAllowed(boolean allowed) {
            this.allowed = allowed;
        }

        public String getHeader() {
            return header;
        }

        public String getFullHeaderText() {
            return raLocaleBean.getMessage("role_page_selected_items", header);
        }

        public String getAccessRule() {
            return accessRule;
        }

        public List<RuleSectionGuiInfo> getRules() {
            return rules;
        }

        public List<RuleSectionGuiInfo> getObjectRules() {
            return objectRules;
        }

        public boolean getAllRulesSelected() {
            for (final RuleSectionGuiInfo rule : rules) {
                if (!rule.allowed) {
                    return false;
                }
            }
            return true;
        }
        
        public AddRemoveListState<RuleSectionGuiInfo> getObjectAddRemoveListState() {
            
        }

//        public boolean getAllObjectRulesSelected() {
//            for (final RuleSectionGuiInfo rule : objectRules) {
//                if (!rule.allowed) {
//                    return false;
//                }
//            }
//            return true;
//        }
    }*/


    public void initialize() throws AuthorizationDeniedException {
        if (initialized) {
            return;
        }
        initialized = true;
        
        if (roleId != null || cloneFromRoleId != null) {
            int roleToFetch = (roleId != null ? roleId : cloneFromRoleId);
            role = raMasterApiProxyBean.getRole(raAuthenticationBean.getAuthenticationToken(), roleToFetch);
            name = role.getRoleName();
            namespace = role.getNameSpace();
            if (roleId == null) {
                role.setRoleId(Role.ROLE_ID_UNASSIGNED); // force creation of a new role if we are cloning
            }
        } else {
            role = new Role("", "");
        }

        namespaceOptions = new ArrayList<>();
        namespaces = raMasterApiProxyBean.getAuthorizedRoleNamespaces(raAuthenticationBean.getAuthenticationToken(), role.getRoleId());
        Collections.sort(namespaces);
        hasAccessToEmptyNamespace = namespaces.contains("");
        if (hasAccessToEmptyNamespace) {
            namespaceOptions.add(new SelectItem("", raLocaleBean.getMessage("role_page_namespace_none")));
            namespaceOptions.add(new SelectItem(NEW_NAMESPACE_ITEM, raLocaleBean.getMessage("role_page_namespace_createnew")));
        }
        for (final String namespace : namespaces) {
            if (!namespace.equals("")) {
                namespaceOptions.add(new SelectItem(namespace, namespace));
            }
        }

        // Get available access rules and their values in this role
        /*ruleSections = new ArrayList<>();

        final IdNameHashMap<CAInfo> authorizedCas = raMasterApiProxyBean.getAuthorizedCAInfos(raAuthenticationBean.getAuthenticationToken());
        if (!authorizedCas.isEmpty()) {
            final RuleSectionGuiInfo section = new RuleSectionGuiInfo(raLocaleBean.getMessage("role_page_section_cas"));

            //section.

            for (final KeyToValueHolder<CAInfo> kv : authorizedCas.values()) {
                final CAInfo ca = kv.getValue();
                section.objectRules.add(new RuleSectionGuiInfo(ca.getName(), "/ca/"+kv.getId()));
            }

            ruleSections.add(section);
        }*/
        
        final IdNameHashMap<CAInfo> authorizedCas = raMasterApiProxyBean.getAuthorizedCAInfos(raAuthenticationBean.getAuthenticationToken());
        for (final KeyToValueHolder<CAInfo> kv : authorizedCas.values()) {
            final CAInfo ca = kv.getValue();
            final String accessRule = StandardRules.CAACCESS.resource() + kv.getId();
            final boolean enabled = AccessRulesHelper.hasAccessToResource(role.getAccessRules(), accessRule);
            caListState.addListItem(accessRule, ca.getName(), enabled);
        }
        
        /*final IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(raAuthenticationBean.getAuthenticationToken(), AccessRulesConstants.VIEW_END_ENTITY);
        for (final KeyToValueHolder<EndEntityProfile> kv : authorizedEndEntityProfiles.values()) {
            final EndEntityProfile profile = kv.getValue();
            final String accessRule = AccessRulesConstants.ENDENTITYPROFILEPREFIX + kv.getId();
            final boolean enabled = AccessRulesHelper.hasAccessToResource(role.getAccessRules(), accessRule);
            endEntityProfileListState.addListItem(accessRule, profile.getName(), enabled);
        }*/
    }

    public Integer getRoleId() { return roleId; }
    public void setRoleId(final Integer roleId) { this.roleId = roleId; }
    public Integer getCloneFromRoleId() { return cloneFromRoleId; }
    public void setCloneFromRoleId(final Integer cloneFromRoleId) { this.cloneFromRoleId = cloneFromRoleId; }
    public Role getRole() { return role; }
    public String getName() { return name; }
    public void setName(final String name) { this.name = name; }
    public String getNamespace() { return namespace; }
    public void setNamespace(final String namespace) { this.namespace = namespace; }
    public String getNewNamespace() { return newNamespace; }
    public void setNewNamespace(final String newNamespace) { this.newNamespace = newNamespace; }
    
    public boolean isLimitedToOneNamespace() {
        return !hasAccessToEmptyNamespace && namespaces.size() == 1;
    }

    public boolean getCanCreateNamespaces() {
        return hasAccessToEmptyNamespace;
    }

    public List<SelectItem> getNamespaceOptions() {
        return namespaceOptions;
    }
    
    public boolean getCanEdit() {
        return raAccessBean.isAuthorizedToEditRoleRules();
    }
    
    public AddRemoveListState<String> getCaListState() { return caListState; }

//    public List<RuleSectionGuiInfo> getRuleSections() {
//        return ruleSections;
//    }
//
//    public void setRuleSections(final List<RuleSectionGuiInfo> ruleSections) {
//        this.ruleSections = ruleSections;
//    }


    public String getPageTitle() {
        if (roleId != null) {
            return raLocaleBean.getMessage("role_page_title_edit", role.getRoleName());
        } else if (cloneFromRoleId != null) {
            return raLocaleBean.getMessage("role_page_title_clone", role.getRoleName());
        } else {
            return raLocaleBean.getMessage("role_page_title_add");
        }
    }

    public String getSaveButtonText() {
        final String messageKey;
        if (roleId != null) {
            messageKey = "role_page_save_command";
        } else if (cloneFromRoleId != null) {
            messageKey = "role_page_clone_command";
        } else {
            messageKey = "role_page_add_command";
        }
        return raLocaleBean.getMessage(messageKey);
    }

    public String save() throws AuthorizationDeniedException {
        // Check and set namespace
        final String namespaceToUse;
        if (!isLimitedToOneNamespace()) {
            if (NEW_NAMESPACE_ITEM.equals(namespace)) {
                if (StringUtils.isBlank(newNamespace)) {
                    log.debug("Empty namespace entered when 'New namespace' was selected, cannot save role");
                    raLocaleBean.addMessageError("role_page_error_empty_namespace");
                    return "";
                }
                namespaceToUse = newNamespace;
            } else {
                namespaceToUse = namespace;
            }
            role.setNameSpace(namespaceToUse);
        }
        role.setRoleName(name);

        // Set access rules
        final Map<String,Boolean> accessMap = role.getAccessRules();
        accessMap.putAll(caListState.getItemStates());

        try {
            role = raMasterApiProxyBean.saveRole(raAuthenticationBean.getAuthenticationToken(), role);
        } catch (RoleExistsException e) {
            if (log.isDebugEnabled()) {
                log.debug("Role named '" + role.getRoleName() + "' in namespace '" + role.getNameSpace() + "' already exists.");
            }
            if (!StringUtils.isEmpty(role.getNameSpace())) {
                raLocaleBean.addMessageError("role_page_error_already_exists_with_namespace", role.getRoleName(), role.getNameSpace());
            } else {
                raLocaleBean.addMessageError("role_page_error_already_exists", role.getRoleName());
            }
            return "";
        }
        roleId = role.getRoleId();
        return "roles?faces-redirect=true&includeViewParams=true";
    }

    public String getDeletePageTitle() {
        return raLocaleBean.getMessage("delete_role_page_title", role.getRoleName());
    }

    public String getDeleteConfirmationText() {
        return raLocaleBean.getMessage("delete_role_page_confirm", role.getAccessRules().size());
    }

    public String delete() throws AuthorizationDeniedException {
        if (!raMasterApiProxyBean.deleteRole(raAuthenticationBean.getAuthenticationToken(), role.getRoleId())) {
            if (log.isDebugEnabled()) {
                log.debug("The role '" + role.getRoleNameFull() + "' could not be deleted. Role ID: " + role.getRoleId());
            }
            raLocaleBean.addMessageError("delete_role_page_error_generic");
            return "";
        }
        return "roles?faces-redirect=true&includeViewParams=true";
    }

    public String cancel() {
        return "roles?faces-redirect=true&includeViewParams=true";
    }

}
