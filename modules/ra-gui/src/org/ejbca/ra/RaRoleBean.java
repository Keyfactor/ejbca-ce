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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.SerializationUtils;
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
import org.ejbca.core.model.era.RaRoleMemberSearchRequest;
import org.ejbca.core.model.era.RaRoleMemberSearchResponse;
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
    /** Matches e.g. /endentityprofilesrules/12345/create_end_entity, but not /endentityprofilesrules/12345 */
    private static final Pattern detailedProfileRulePattern = Pattern.compile(".*/([-0-9]+)/.+$");

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
    
    /** Represents a checkbox for a rule in the GUI */
    public final class RuleCheckboxInfo implements Serializable {
        private static final long serialVersionUID = 2L;
        private final List<String> accessRules;
        private final String label;
        private boolean allowed;

        public RuleCheckboxInfo(final List<String> accessRules, final String labelMessageKey) {
            this.accessRules = accessRules;
            this.label = raLocaleBean.getMessage(labelMessageKey);
            this.allowed = accessRules.stream().allMatch(accessRule -> AccessRulesHelper.hasAccessToResource(role.getAccessRules(), accessRule));
        }

        public List<String> getAccessRules() {
            return accessRules;
        }
        
        public String getLabel() { return label; }
        public boolean isAllowed() { return allowed; }
        public void setAllowed(final boolean allowed) { this.allowed = allowed; }
    }

    private List<RuleCheckboxInfo> endEntityRules = new ArrayList<>();
    private AddRemoveListState<String> caListState = new AddRemoveListState<>();
    private AddRemoveListState<String> endEntityProfileListState = new AddRemoveListState<>();
    private Map<Integer,String> eeProfilesWithCustomPermissions = new HashMap<>();
    
    public void initialize() throws AuthorizationDeniedException {
        if (initialized) {
            return;
        }
        initialized = true;
        
        // Get namespaces
        namespaceOptions = new ArrayList<>();
        namespaces = raMasterApiProxyBean.getAuthorizedRoleNamespaces(raAuthenticationBean.getAuthenticationToken(), roleId != null ? roleId : Role.ROLE_ID_UNASSIGNED);
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
        
        // Get role
        if (roleId != null || cloneFromRoleId != null) {
            int roleToFetch = (roleId != null ? roleId : cloneFromRoleId);
            role = raMasterApiProxyBean.getRole(raAuthenticationBean.getAuthenticationToken(), roleToFetch);
            name = role.getRoleName();
            namespace = role.getNameSpace();
            if (roleId == null) {
                role.setRoleId(Role.ROLE_ID_UNASSIGNED); // force creation of a new role if we are cloning
            }
        } else {
            role = new Role(getDefaultNamespace(), "");
        }

        // Get available access rules and their values in this role
        final IdNameHashMap<CAInfo> authorizedCas = raMasterApiProxyBean.getAuthorizedCAInfos(raAuthenticationBean.getAuthenticationToken());
        for (final KeyToValueHolder<CAInfo> kv : authorizedCas.values()) {
            final CAInfo ca = kv.getValue();
            final String accessRule = StandardRules.CAACCESS.resource() + kv.getId();
            final boolean enabled = AccessRulesHelper.hasAccessToResource(role.getAccessRules(), accessRule);
            caListState.addListItem(accessRule, ca.getName(), enabled);
        }
        
        final IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(raAuthenticationBean.getAuthenticationToken(), AccessRulesConstants.VIEW_END_ENTITY);
        // Only allow end entity profiles with either full or no access to be edited
        for (final String accessRule : role.getAccessRules().keySet()) {
            if (accessRule.startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
                final Matcher matcher = detailedProfileRulePattern.matcher(accessRule);
                if (matcher.matches()) {
                    int profileId = Integer.parseInt(matcher.group(1));
                    eeProfilesWithCustomPermissions.put(profileId, authorizedEndEntityProfiles.get(profileId).getName());
                }
            }
        }
        for (final KeyToValueHolder<EndEntityProfile> kv : authorizedEndEntityProfiles.values()) {
            if (!eeProfilesWithCustomPermissions.containsKey(kv.getId())) {
                final String accessRule = AccessRulesConstants.ENDENTITYPROFILEPREFIX + kv.getId();
                final boolean enabled = AccessRulesHelper.hasAccessToResource(role.getAccessRules(), accessRule);
                endEntityProfileListState.addListItem(accessRule, kv.getName(), enabled);
            }
        }
        endEntityRules.add(new RuleCheckboxInfo(Arrays.asList(AccessRulesConstants.REGULAR_APPROVEENDENTITY, AccessRulesConstants.REGULAR_VIEWAPPROVALS), "role_page_access_approveendentity"));
        endEntityRules.add(new RuleCheckboxInfo(Arrays.asList(AccessRulesConstants.REGULAR_CREATEENDENTITY, AccessRulesConstants.REGULAR_DELETEENDENTITY), "role_page_access_createdeleteendentity"));
        endEntityRules.add(new RuleCheckboxInfo(Arrays.asList(AccessRulesConstants.REGULAR_CREATECERTIFICATE), "role_page_access_create_certificate"));
        endEntityRules.add(new RuleCheckboxInfo(Arrays.asList(AccessRulesConstants.REGULAR_EDITENDENTITY), "role_page_access_editendentity"));
        endEntityRules.add(new RuleCheckboxInfo(Arrays.asList(AccessRulesConstants.REGULAR_REVOKEENDENTITY), "role_page_access_revokeendentity"));
        endEntityRules.add(new RuleCheckboxInfo(Arrays.asList(AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRulesConstants.REGULAR_VIEWCERTIFICATE), "role_page_access_viewendentity_and_certificates"));
        endEntityRules.add(new RuleCheckboxInfo(Arrays.asList(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY), "role_page_access_viewendentityhistory"));
    }
    
    public String getDefaultNamespace() {
        if (isLimitedToOneNamespace() || namespaces.isEmpty()) { // should never be empty, but better safe than sorry
            return "";
        } else {
            return namespaces.get(0);
        }
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
    
    public boolean getHasCustomEndEntityProfilePermissions() {
        return !eeProfilesWithCustomPermissions.isEmpty();
    }
    
    public String getCustomEndEntityProfilePermissionsNotice() {
        final String profileList = StringUtils.join(eeProfilesWithCustomPermissions.values(), ", ");
        return raLocaleBean.getMessage("role_page_custom_permissions_endentityprofiles", profileList);
    }
    
    public List<RuleCheckboxInfo> getEndEntityRules() { return endEntityRules; }
    public AddRemoveListState<String> getCaListState() { return caListState; }
    public AddRemoveListState<String> getEndEntityProfileListState() { return endEntityProfileListState; }


    public String getPageTitle() {
        if (!getCanEdit()) {
            return raLocaleBean.getMessage("role_page_title_view", role.getRoleName());
        } else if (roleId != null) {
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
        // The getRole method returns a reference to an object which should not be edited directly,
        // so we make a deep copy of it here, which we can edit freely. This code is not performance critical,
        // so cloning through serialization is OK (and does not require a copy constructor that needs to be maintained).
        final Role roleWithChanges = (Role) SerializationUtils.clone(role);
        // Check and set namespace
        if (!isLimitedToOneNamespace()) {
            final String namespaceToUse;
            if (NEW_NAMESPACE_ITEM.equals(namespace)) {
                if (StringUtils.isBlank(newNamespace)) {
                    log.debug("Empty namespace entered when 'New namespace' was selected. Cannot save role");
                    raLocaleBean.addMessageError("role_page_error_empty_namespace");
                    return "";
                }
                namespaceToUse = newNamespace;
            } else {
                if (!StringUtils.isBlank(newNamespace)) {
                    log.debug("New namespace name entered when an existing namespace was selected. Cannot save role");
                    raLocaleBean.addMessageError("role_page_error_new_and_existing_namespace");
                    return "";
                }
                namespaceToUse = namespace;
            }
            roleWithChanges.setNameSpace(namespaceToUse);
        } else if (role.getRoleId() == Role.ROLE_ID_UNASSIGNED) {
            // New role, and the admin is only allowed to use one namespace. Set the namespace to the only allowed one
            roleWithChanges.setNameSpace(namespaces.get(0));
        }
        roleWithChanges.setRoleName(name);

        // Set access rules
        final Map<String,Boolean> accessMap = roleWithChanges.getAccessRules();
        for (final RuleCheckboxInfo checkboxInfo : endEntityRules) {
            checkboxInfo.getAccessRules().forEach(accessRule -> accessMap.put(accessRule, checkboxInfo.allowed));
        }
        accessMap.putAll(caListState.getItemStates());
        accessMap.putAll(endEntityProfileListState.getItemStates());

        try {
            role = raMasterApiProxyBean.saveRole(raAuthenticationBean.getAuthenticationToken(), roleWithChanges);
        } catch (RoleExistsException e) {
            if (log.isDebugEnabled()) {
                log.debug("Role named '" + roleWithChanges.getRoleName() + "' in namespace '" + roleWithChanges.getNameSpace() + "' already exists.");
            }
            if (!StringUtils.isEmpty(roleWithChanges.getNameSpace())) {
                raLocaleBean.addMessageError("role_page_error_already_exists_with_namespace", roleWithChanges.getRoleName(), roleWithChanges.getNameSpace());
            } else {
                raLocaleBean.addMessageError("role_page_error_already_exists", roleWithChanges.getRoleName());
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
        // Find out how many role members this role has
        final RaRoleMemberSearchRequest searchRequest = new RaRoleMemberSearchRequest();
            searchRequest.setRoleIds(new ArrayList<>(Arrays.asList(role.getRoleId())));
        //searchRequest.setGenericSearchString(genericSearchString);
        final RaRoleMemberSearchResponse response = raMasterApiProxyBean.searchForRoleMembers(raAuthenticationBean.getAuthenticationToken(), searchRequest);
        return raLocaleBean.getMessage("delete_role_page_confirm", response.getRoleMembers().size());
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
