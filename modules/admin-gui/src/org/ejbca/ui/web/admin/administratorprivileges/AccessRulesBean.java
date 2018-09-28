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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Managed Bean for the Role's access rules pages:
 * - Basic mode access rule configuration
 * - Advanced mode access rule configuration
 * - Advanced mode access rule summary
 *
 * @version $Id$
 */
@ViewScoped
@ManagedBean
public class AccessRulesBean extends BaseManagedBean implements Serializable {

    /** Basic mode access rule holder */
    private static class AccessRule {
        private final String resource;
        private final boolean state;

        AccessRule(final String resource, final boolean state) {
            this.resource = AccessRulesHelper.normalizeResource(resource);
            this.state = state;
        }
    }

    /** Basic mode access rule holder sorted by section */
    private static class AccessRulesTemplate {
        private final String name;
        private final HashMap<String,Boolean> accessRules = new HashMap<>();

        public AccessRulesTemplate(final String name, final AccessRule...accessRules) {
            this.name = name;
            for (final AccessRule accessRule : accessRules) {
                this.getAccessRules().put(accessRule.resource, accessRule.state);
            }
            AccessRulesHelper.normalizeResources(this.accessRules);
            AccessRulesHelper.minimizeAccessRules(this.accessRules);
        }

        public String getName() { return name; }
        public HashMap<String,Boolean> getAccessRules() { return accessRules; }
    }

    /** Advanced mode access rule holder sorted for a category */
    public static class AccessRuleCollection {
        private String name;
        private List<AccessRuleItem> collection;

        public AccessRuleCollection(String name, List<AccessRuleItem> collection) {
            this.name = name;
            this.collection = collection;
        }

        public String getName() { return name; }
        public List<AccessRuleItem> getCollection() { return collection; }
    }

    /** Advanced mode access rule tri-state */
    private static enum AccessRuleState {
        UNDEFINED, ALLOW, DENY;

        static AccessRuleState toAccessRuleState(final Boolean state) {
            return state==null ? UNDEFINED : state ? ALLOW : DENY;
        }
    }

    /** Advanced mode access rule representation */
    public static class AccessRuleItem implements Comparable<AccessRuleItem>, Serializable {
        private static final long serialVersionUID = 1L;

        private final String category;
        private final String resource;
        private final String resourceName;
        private final String resourceMain;
        private final String resourceSub;
        private AccessRuleState state = AccessRuleState.UNDEFINED;

        public AccessRuleItem(final String category, final String resource, final String resourceName) {
            this.category = category;
            this.resource = AccessRulesHelper.normalizeResource(resource);
            this.resourceName = resourceName==null ? this.resource : AccessRulesHelper.normalizeResource(resourceName);
            final String[] resourceSplit = this.resourceName.split("/");
            if (resourceSplit.length==0) {
                this.resourceSub = "/";
                this.resourceMain = "";
            } else {
                this.resourceSub = resourceSplit[resourceSplit.length-1] + "/";
                String resourceMain = "/";
                for (int i=1; i<resourceSplit.length-1; i++) {
                    resourceMain += resourceSplit[i] + "/";
                }
                this.resourceMain = resourceMain;
            }
        }

        /** @return the category this resource belongs to */
        public String getCategory() { return category; }
        /** @return the normalized resource with Id kept intact for objects */
        public String getResource() { return resource; }
        /** @return the normalized resource with Id replaced by names for objects */
        public String getResourceName() { return resourceName; }
        /** @return the first part(s) of the resourceName e.g.  '/mainrule/subrule/' from '/mainrule/subrule/subsubrule/' */
        public String getResourceMain() { return resourceMain; }
        /** @return the last part of the resourceName e.g. 'subsubrule/' from '/mainrule/subrule/subsubrule/' */
        public String getResourceSub() { return resourceSub; }
        /** @return one of the {@link AccessRuleState} enum names representing the current state of this rule */
        public String getState() { return state.name(); }
        /** Set one of the {@link AccessRuleState} enum names representing the current state of this rule */
        public void setState(String state) { this.state = AccessRuleState.valueOf(state); }
        /** @return one of the {@link AccessRuleState} enum representing the current state of this rule */
        private AccessRuleState getStateEnum() { return state; }
        /** @return true if the resource in this istance is '/' */
        public boolean isRootResource() { return StandardRules.ROLE_ROOT.resource().equals(resource); }

        @Override
        public int compareTo(final AccessRuleItem other) {
            // Sort by resource name (with IDs replaced by names)
            return getResourceName().compareToIgnoreCase(other.getResourceName());
        }
    }

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AccessRulesBean.class);

    private static final String TEMPLATE_NAME_CUSTOM = "CUSTOM";

    private static final List<AccessRulesTemplate> accessRulesTemplates = Arrays.asList(
            new AccessRulesTemplate("SUPERVISOR",
                    new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, Role.STATE_ALLOW),
                    new AccessRule(AuditLogRules.VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, Role.STATE_ALLOW),
                    // From legacy JS
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWHARDTOKENS, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITY, Role.STATE_ALLOW)
                    ),
            new AccessRulesTemplate("AUDITOR",
                    new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, Role.STATE_ALLOW),
                    new AccessRule(AuditLogRules.VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, Role.STATE_ALLOW),
                    new AccessRule(InternalKeyBindingRules.VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CAVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CERTIFICATEPROFILEVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.APPROVALPROFILEVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(CryptoTokenRules.VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWPUBLISHER, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWVALIDATOR, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.SERVICES_VIEW, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW, Role.STATE_ALLOW),
                    new AccessRule(StandardRules.SYSTEMCONFIGURATION_VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.EKUCONFIGURATION_VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.VIEWROLES.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, Role.STATE_ALLOW)
                    ),
            new AccessRulesTemplate("RAADMINISTRATOR",
                    new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_CREATECERTIFICATE, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, Role.STATE_ALLOW),
                    // From legacy JS
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_CREATEENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_EDITENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_DELETEENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_REVOKEENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_KEYRECOVERY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_APPROVEENDENTITY, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWPUKS, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWAPPROVALS, Role.STATE_ALLOW),
                    new AccessRule(AuditLogRules.VIEW.resource(), Role.STATE_ALLOW)
                    ),
            new AccessRulesTemplate("CAADMINISTRATOR",
                    new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CAFUNCTIONALITY.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CAVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.CERTIFICATEPROFILEVIEW.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_EDITPUBLISHER, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWPUBLISHER, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_EDITVALIDATOR, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_VIEWVALIDATOR, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_EDITBLACKLIST, Role.STATE_ALLOW),
                    new AccessRule(StandardRules.VALIDATORACCESSBASE.resource(), Role.STATE_ALLOW),
                    // This was present in legacy DefaultRoles, but makes very little sense
                    //new AccessRule(AuditLogRules.LOG.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.REGULAR_RAFUNCTIONALITY, Role.STATE_ALLOW),
                    new AccessRule(StandardRules.EDITROLES.resource(), Role.STATE_ALLOW),
                    new AccessRule(StandardRules.VIEWROLES.resource(), Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.ENDENTITYPROFILEBASE, Role.STATE_ALLOW),
                    //new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS, Role.STATE_ALLOW),
                    new AccessRule(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES, Role.STATE_ALLOW),
                    new AccessRule(CryptoTokenRules.VIEW.resource(), Role.STATE_ALLOW),
                    /*
                     * Note:
                     * We DO NOT allow CA Administrators to USE CryptoTokens, since this would mean that they could
                     * bind any existing CryptoToken to a new CA and access the keys.
                     * new AccessRule(CryptoTokenRules.USE.resource(), Role.STATE_ALLOW)
                     */
                    new AccessRule(InternalKeyBindingRules.DELETE.resource(), Role.STATE_ALLOW),
                    new AccessRule(InternalKeyBindingRules.MODIFY.resource(), Role.STATE_ALLOW),
                    new AccessRule(InternalKeyBindingRules.VIEW.resource(), Role.STATE_ALLOW),
                    // From legacy JS
                    new AccessRule(AuditLogRules.VIEW.resource(), Role.STATE_ALLOW)
                    ),
            new AccessRulesTemplate("SUPERADMINISTRATOR", new AccessRule(StandardRules.ROLE_ROOT.resource(), Role.STATE_ALLOW)),
            // Ignore the legacy "HARDTOKENISSUER" template since it is rarely used
            //,new AccessRulesTemplate("HARDTOKENISSUER")
            new AccessRulesTemplate(TEMPLATE_NAME_CUSTOM)
            );

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private AuthorizationSystemSessionLocal authorizationSystemSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;
    @EJB
    private RoleSessionLocal roleSession;

    private Map<Integer, String> caIdToNameMap;
    private Map<Integer, String> eepIdToNameMap;
    private Map<Integer, String> keyValidatorsIdToNameMap;
    private String roleIdParam;
    private String advancedParam;
    private String summaryParam;
    private Role role;

    private String accessRulesTemplateSelected = TEMPLATE_NAME_CUSTOM;
    private List<SelectItem> availableAccessRulesTemplates = null;
    private List<String> resourcesCaSelected = new ArrayList<>();
    private LinkedList<SelectItem> availableResourcesCa = null;
    private List<String> resourcesEeSelected = new ArrayList<>();
    private List<SelectItem> availableResourcesEe = null;
    private List<String> resourcesEepSelected = new ArrayList<>();
    private LinkedList<SelectItem> availableResourcesEep = null;
    private List<String> resourcesKeyValidatorsSelected = new ArrayList<>();
    private LinkedList<SelectItem> availableResourcesKeyValidators = null;
    private List<String> resourcesIkbSelected = new ArrayList<>();
    private List<SelectItem> availableResourcesIkb = null;
    private List<String> resourcesOtherSelected = new ArrayList<>();
    private List<SelectItem> availableResourcesOther = null;

    private List<AccessRuleItem> authorizedAccessRuleItems = null;
    private final List<SelectItem> availableAccessRuleStates = new ArrayList<>();

    @PostConstruct
    private void postConstruct() {
        final Map<String, String> requestParameterMap = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap();
        // Read HTTP param "roleId" that should be interpreted as an integer
        roleIdParam = requestParameterMap.get("roleId");
        // Read HTTP param "advanced" that should be interpreted as an boolean
        advancedParam = requestParameterMap.get("advanced");
        // Read HTTP param "summary" that should be interpreted as an boolean
        summaryParam = requestParameterMap.get("summary");
        caIdToNameMap = caSession.getCAIdToNameMap();
        eepIdToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        keyValidatorsIdToNameMap = keyValidatorSession.getKeyValidatorIdToNameMap();
        reinitSelection();
    }

    /** Perform POST-REDIRECT-GET when this method is invoked from a non-AJAX context. */
    private void nonAjaxPostRedirectGet() {
        String requestParams = "?roleId=" + role.getRoleId();
        if (isAdvancedMode()) {
            requestParams += "&advanced=true";
            if (isAdvancedModeSummary()) {
                requestParams += "&summary=true";
            }
        }
        super.nonAjaxPostRedirectGet(requestParams);
    }

    /** @return true in advanced access rule mode */
    public boolean isAdvancedMode() {
        return Boolean.parseBoolean(advancedParam);
    }

    /** @return true in advanced access rule mode */
    public boolean isAdvancedModeSummary() {
        return Boolean.parseBoolean(summaryParam);
    }

    /** @return true when admin is authorized to edit access rules of this role */
    public boolean isAuthorizedToEditRole() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EDITROLES.resource()) && getRole()!=null;
    }

    /** @return an authorized existing role based on the roleId HTTP param or null if no such role was found. */
    public Role getRole() {
        if (role==null && NumberUtils.isNumber(roleIdParam)) {
            try {
                role = roleSession.getRole(getAdmin(), Integer.parseInt(roleIdParam));
                if (role==null && log.isDebugEnabled()) {
                    log.debug("Admin '" + getAdmin() + "' failed to access non-existing role.");
                }
            } catch (NumberFormatException | AuthorizationDeniedException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Admin '" + getAdmin() + "' failed to access a role: " + e.getMessage());
                }
            }
        }
        return role;
    }

    /** Recalculate selection based on current state of template selection or loaded role's access rules */
    private void reinitSelection() {
        // Reset available lists that might be rendered differently depending on selected template
        availableResourcesCa = null;
        availableResourcesEe = null;
        availableResourcesEep = null;
        availableResourcesKeyValidators = null;
        availableResourcesIkb = null;
        availableResourcesOther = null;
        // Calculate available templates and the current best match
        getAvailableAccessRulesTemplates();
        // Select access rules that are allowed by the role
        final LinkedHashMap<String, Boolean> accessRules = getRole().getAccessRules();
        // Find CA access resources allowed by this role
        setResourcesCaSelected(getSelectedRulesFromIdentifiers(accessRules, StandardRules.CAACCESS.resource(), caIdToNameMap.keySet()));
        // Find RA resources allowed by this role
        setResourcesEeSelected(getSelectedRulesFromSelectItems(accessRules, getAvailableResourcesEe()));
        // Find EEP resources allowed by this role
        setResourcesEepSelected(getSelectedRulesFromIdentifiers(accessRules, AccessRulesConstants.ENDENTITYPROFILEPREFIX, eepIdToNameMap.keySet(), getAvailableResourcesEe()));
        // Find KV resources allowed by this role
        setResourcesKeyValidatorsSelected(getSelectedRulesFromIdentifiers(accessRules, StandardRules.VALIDATORACCESS.resource(), keyValidatorsIdToNameMap.keySet()));
        // Find IKB resources allowed by this role
        setResourcesIkbSelected(getSelectedRulesFromSelectItems(accessRules, getAvailableResourcesIkb()));
        // Find Other resources allowed by this role
        setResourcesOtherSelected(getSelectedRulesFromSelectItems(accessRules, getAvailableResourcesOther()));
    }

    /** @return minimal list of resources that the provided access rules grants */
    private List<String> getSelectedRulesFromIdentifiers(final LinkedHashMap<String, Boolean> accessRules, final String baseResource, final Set<Integer> ids) {
        final List<String> ret = new ArrayList<>();
        if (AccessRulesHelper.hasAccessToResource(accessRules, baseResource)) {
            ret.add(baseResource);
        } else {
            for (final int id : ids) {
                final String resource = AccessRulesHelper.normalizeResource(baseResource + id);
                if (AccessRulesHelper.hasAccessToResource(accessRules, resource)) {
                    ret.add(resource);
                }
            }
        }
        return ret;
    }
    
    /**
     * Like {@link #getSelectedRulesFromIdentifiers}, but also includes rules that have all enabled sub-rules present.
     * (example: if "Create End Entity" and "Edit End Entity" are selected, then it will also include all profiles that have those items allowed)
     */
    private List<String> getSelectedRulesFromIdentifiers(final LinkedHashMap<String, Boolean> accessRules, final String baseResource, final Set<Integer> ids,
            final List<SelectItem> selectedSubRules) {
        // Get all items that are allowed recursively
        final List<String> ret = getSelectedRulesFromIdentifiers(accessRules, baseResource, ids);
        // Also add items where all allowed sub-rules are explicitly allowed for the item
        for (final int id : ids) {
            final String resource = AccessRulesHelper.normalizeResource(baseResource + id);
            if (ret.contains(resource)) {
                continue; // Don't add twice
            }
            boolean allSubRulesAllowed = true;
            for (final SelectItem selectedSubRule : selectedSubRules) {
                final String subRule = String.valueOf(selectedSubRule.getValue()).replace(AccessRulesConstants.REGULAR_RAFUNCTIONALITY + "/", "");
                if (!accessRules.containsKey(resource + subRule)) {
                    allSubRulesAllowed = false;
                    break;
                }
            }
            if (allSubRulesAllowed) {
                if (log.isDebugEnabled()) {
                    log.debug("Item " + resource + " is considered to be allowed, since all allowed sub-rules are also allowed for this item");
                }
                ret.add(resource);
            }
        }
        return ret;
    }

    /** @return minimal list of resources that the provided access rules grants */
    private List<String> getSelectedRulesFromSelectItems(final LinkedHashMap<String, Boolean> accessRules, final List<SelectItem> selectItems) {
        final List<String> ret = new ArrayList<>();
        for (final SelectItem selectItem : selectItems) {
            final String resource = AccessRulesHelper.normalizeResource(String.valueOf(selectItem.getValue()));
            if (AccessRulesHelper.hasAccessToResource(getRole().getAccessRules(), resource)) {
                ret.add(resource);
            }
        }
        return ret;
    }

    /** @return the currently select role template */
    public String getAccessRulesTemplateSelected() { return accessRulesTemplateSelected; }
    /** Set the currently select role template */
    public void setAccessRulesTemplateSelected(String accessRulesTemplateSelected) { this.accessRulesTemplateSelected = accessRulesTemplateSelected; }

    /** @return true if this role is assumed to have been configured outside of the basic mode */
    public boolean isAccessRulesTemplateCustom() { return TEMPLATE_NAME_CUSTOM.equals(getAccessRulesTemplateSelected()); }
    /** @return true if this role is assumed to have been configured using the CAAdministrator template */
    private boolean isAccessRulesTemplateCaAdmin() { return "CAADMINISTRATOR".equals(getAccessRulesTemplateSelected()); }
    /** @return true if this role is assumed to have been configured using the SuperAdministrator template */
    private boolean isAccessRulesTemplateSuperAdmin() { return "SUPERADMINISTRATOR".equals(getAccessRulesTemplateSelected()); }
    /** @return true if this role is assumed to have been configured using RaAdministrator template */
    private boolean isAccessRulesTemplateRaAdmin() {return "RAADMINISTRATOR".equals(getAccessRulesTemplateSelected());}

    /** @return currently selected AccessRuleTemplate */
    private AccessRulesTemplate getAccessRulesTemplate() {
        for (final AccessRulesTemplate accessRulesTemplate : accessRulesTemplates) {
            if (accessRulesTemplate.getName().equals(getAccessRulesTemplateSelected())) {
                return accessRulesTemplate;
            }
        }
        return null;
    }

    /** Invoked by the user when changing selected template and JavaScript is enabled */
    public void actionAccessRulesTemplateSelectAjaxListener(final AjaxBehaviorEvent event) {
        actionAccessRulesTemplateSelect();
    }

    /** Invoked by the user when changing selected template and JavaScript is disabled (or via the AJAX call) */
    public void actionAccessRulesTemplateSelect() {
        final AccessRulesTemplate accessRulesTemplate = getAccessRulesTemplate();
        final LinkedHashMap<String, Boolean> accessRules = getRole().getAccessRules();
        accessRules.clear();
        accessRules.putAll(accessRulesTemplate.getAccessRules());
        reinitSelection();
        if (!isAccessRulesTemplateCustom()) {
            // Remove the CUSTOM template from the list of selectable templates since it is really configured in advanced mode
            removeAccessRulesTemplateCustomOption();
        }
    }

    /** @return a list of available access rules templates (and detects the best match to the existing role's rules for performance reasons at the same time) */
    public List<SelectItem> getAvailableAccessRulesTemplates() {
        if (availableAccessRulesTemplates==null) {
            availableAccessRulesTemplates = new ArrayList<>();
            for (final AccessRulesTemplate accessRulesTemplate : accessRulesTemplates) {
                // Ensure that current admin is authorized to all access rules implied by the template
                final List<String> allowedResources = new ArrayList<>();
                // Ensure that there is no access rule in role that is not covered by template to check for a match
                if (getRole() != null) {
                    if (getRole().getAccessRules() != null) {
                        final HashMap<String, Boolean> remainingAccessRulesInRole = new HashMap<>(getRole().getAccessRules());
                        AccessRulesHelper.normalizeResources(remainingAccessRulesInRole);
                        AccessRulesHelper.minimizeAccessRules(remainingAccessRulesInRole);
                        filterOutSelectItems(remainingAccessRulesInRole, getAvailableResourcesCa());
                        filterOutSelectItems(remainingAccessRulesInRole, getAvailableResourcesEep());
                        filterOutSelectItems(remainingAccessRulesInRole, getAvailableResourcesKeyValidators());
                        for (final Entry<String, Boolean> entry : accessRulesTemplate.getAccessRules().entrySet()) {
                            if (entry.getValue().booleanValue()) {
                                final String resource = entry.getKey();
                                allowedResources.add(resource);
                                remainingAccessRulesInRole.remove(AccessRulesHelper.normalizeResource(resource));
                            }
                        }
                        if (authorizationSession.isAuthorizedNoLogging(getAdmin(), allowedResources.toArray(new String[0]))) {
                            availableAccessRulesTemplates.add(
                                    new SelectItem(accessRulesTemplate.getName(), super.getEjbcaWebBean().getText(accessRulesTemplate.getName())));
                            // Check if this template matches the Role's current access rules
                            if (remainingAccessRulesInRole.isEmpty()) {
                                accessRulesTemplateSelected = accessRulesTemplate.getName();
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("Role '" + getRole().getRoleNameFull() + "' does not qualify as a '" + accessRulesTemplate.getName()
                                            + "'. Extra rules: " + Arrays.toString(remainingAccessRulesInRole.keySet().toArray()));
                                }
                            }
                        }
                    } else {
                        if(log.isDebugEnabled()) {
                            log.debug("Role with name " + role.getRoleName() + " returned a null access rule list.");
                        }
                    }
                } else {
                    if(log.isDebugEnabled()) {
                        log.debug("Role with ID " + roleIdParam + " could not be retrieved from the database.");
                    }
                }
            }
            super.sortSelectItemsByLabel(availableAccessRulesTemplates);
        }
        return availableAccessRulesTemplates;
    }

    private void removeAccessRulesTemplateCustomOption() {
        for (final SelectItem selectItem : new ArrayList<>(availableAccessRulesTemplates)) {
            if (selectItem.getValue().equals(TEMPLATE_NAME_CUSTOM)) {
                availableAccessRulesTemplates.remove(selectItem);
                break;
            }
        }
    }

    /** @return true if the CA selection box should be modifiable */
    public boolean isRenderResourcesCaSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin();
    }

    /** @return the currently selected CA access resources */
    public List<String> getResourcesCaSelected() { return resourcesCaSelected; }
    /** Set the currently selected CA access resources */
    public void setResourcesCaSelected(final List<String> resourcesCaSelected) { this.resourcesCaSelected = new ArrayList<>(resourcesCaSelected); }

    /** @return the selectable CA access resources */
    public List<SelectItem> getAvailableResourcesCa() {
        if (availableResourcesCa==null) {
            availableResourcesCa = new LinkedList<>();
            for (final int caId : caSession.getAuthorizedCaIds(getAdmin())) {
                final String name = caIdToNameMap.containsKey(caId) ? caIdToNameMap.get(caId) : String.valueOf(caId);
                availableResourcesCa.add(new SelectItem(AccessRulesHelper.normalizeResource(StandardRules.CAACCESS.resource() + caId), name));
            }
            super.sortSelectItemsByLabel(availableResourcesCa);
            if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CAACCESS.resource())) {
                availableResourcesCa.addFirst(new SelectItem(StandardRules.CAACCESS.resource(), super.getEjbcaWebBean().getText("ALL")));
            }
        }
        return availableResourcesCa;
    }

    /** @return true if the RA rules selection box should be modifiable */
    public boolean isRenderResourcesEeSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin() && !isAccessRulesTemplateCaAdmin();
    }

    /** @return the currently selected RA functionality resources */
    public List<String> getResourcesEeSelected() { return resourcesEeSelected; }
    /** Set the currently selected RA functionality resources */
    public void setResourcesEeSelected(final List<String> resourcesEeSelected) { this.resourcesEeSelected = new ArrayList<>(resourcesEeSelected); }

    /** @return the selectable RA functionality resources */
    public List<SelectItem> getAvailableResourcesEe() {
        if (availableResourcesEe==null) {
            availableResourcesEe = new ArrayList<>(Arrays.asList(
                    // Not part of basic mode
                    //new SelectItem(AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES, super.getEjbcaWebBean().getText("EDITENDENTITYPROFILES")),
                    //new SelectItem(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, super.getEjbcaWebBean().getText("VIEWENDENTITYPROFILES")),
                    //new SelectItem(AccessRulesConstants.REGULAR_EDITUSERDATASOURCES, super.getEjbcaWebBean().getText("EDITUSERDATASOURCES")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_APPROVEENDENTITY), super.getEjbcaWebBean().getText("APPROVEENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_REVOKEENDENTITY), super.getEjbcaWebBean().getText("REVOKEENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_VIEWENDENTITY), super.getEjbcaWebBean().getText("VIEWENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_CREATEENDENTITY), super.getEjbcaWebBean().getText("CREATEENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_EDITENDENTITY), super.getEjbcaWebBean().getText("EDITENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_DELETEENDENTITY), super.getEjbcaWebBean().getText("DELETEENDENTITYRULE")),
                    new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY), super.getEjbcaWebBean().getText("VIEWHISTORYRULE"))
                    ));
            if (isEnabledIssueHardwareTokens()) {
                availableResourcesEe.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_VIEWHARDTOKENS), super.getEjbcaWebBean().getText("VIEWHARDTOKENRULE")));
                availableResourcesEe.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_VIEWPUKS), super.getEjbcaWebBean().getText("VIEWPUKENDENTITYRULE")));
            }
            if (isEnabledKeyRecovery()) {
                availableResourcesEe.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_KEYRECOVERY), super.getEjbcaWebBean().getText("KEYRECOVERENDENTITYRULE")));
            }
            // Disable the selections what it not allowed by current template
            for (final SelectItem selectItem : availableResourcesEe) {
                if (!AccessRulesHelper.hasAccessToResource(getAccessRulesTemplate().getAccessRules(), String.valueOf(selectItem.getValue()))) {
                    selectItem.setDisabled(true);
                }
            }
            super.sortSelectItemsByLabel(availableResourcesEe);
        }
        return availableResourcesEe;
    }

    /** @return true if the End Entity Profile rule selection box should be modifiable */
    public boolean isRenderResourcesEepSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin() && !isAccessRulesTemplateCaAdmin();
    }

    /** @return the currently selected EEP resources */
    public List<String> getResourcesEepSelected() { return resourcesEepSelected; }
    /** Set the currently selected EEP resources */
    public void setResourcesEepSelected(final List<String> resourcesEepSelected) { this.resourcesEepSelected = new ArrayList<>(resourcesEepSelected); }

    /** @return the selectable EEP resources */
    public List<SelectItem> getAvailableResourcesEep() {
        if (availableResourcesEep==null) {
            availableResourcesEep = new LinkedList<>();
            for (final int eepId : endEntityProfileSession.getAuthorizedEndEntityProfileIds(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITY)) {
                final String name = eepIdToNameMap.containsKey(eepId) ? eepIdToNameMap.get(eepId) : String.valueOf(eepId);
                availableResourcesEep.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId), name));
            }
            super.sortSelectItemsByLabel(availableResourcesEep);
            if (authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
                availableResourcesEep.addFirst(new SelectItem(AccessRulesConstants.ENDENTITYPROFILEPREFIX, super.getEjbcaWebBean().getText("ALL")));
            }
        }
        return availableResourcesEep;
    }

    /** @return true if the key validator rule selection box should be modifiable */
    public boolean isRenderResourcesKvSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin() && !isAccessRulesTemplateRaAdmin();
    }

    /** @return the currently selected key validator resources */
    public List<String> getResourcesKeyValidatorsSelected() { return resourcesKeyValidatorsSelected; }

    /** Set the currently selected key validator resources */
    public void setResourcesKeyValidatorsSelected(final List<String> resourcesKeyValidatorsSelected) {
        this.resourcesKeyValidatorsSelected = new ArrayList<>(resourcesKeyValidatorsSelected);
    }

    /** @return the selectable key validator resources */
    public List<SelectItem> getAvailableResourcesKeyValidators() {
        if (availableResourcesKeyValidators==null) {
            availableResourcesKeyValidators = new LinkedList<>();
            final Collection<Integer> authorizedKvIds = keyValidatorSession.getAuthorizedKeyValidatorIds(getAdmin(), AccessRulesConstants.REGULAR_VIEWVALIDATOR);
            if (log.isDebugEnabled()) {
                log.debug("Authorized key validator ids for " + getAdmin().getUniqueId() + " are " + authorizedKvIds);
            }
            for (final int id : authorizedKvIds) {
                availableResourcesKeyValidators.add(new SelectItem(AccessRulesHelper.normalizeResource(StandardRules.VALIDATORACCESS.resource() + id), keyValidatorsIdToNameMap.get(id)));
            }
            super.sortSelectItemsByLabel(availableResourcesKeyValidators);
            if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.VALIDATORACCESS.resource())) {
                availableResourcesKeyValidators.addFirst(new SelectItem(StandardRules.VALIDATORACCESS.resource(), super.getEjbcaWebBean().getText("ALL")));
            }
        }
        return availableResourcesKeyValidators;
    }

    /** @return true if the InternalKeyBinding rule selection box should be modifiable */
    public boolean isRenderResourcesIkbSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin();
    }

    /** @return the currently selected IKB resources */
    public List<String> getResourcesIkbSelected() { return resourcesIkbSelected; }
    /** Set the currently selected IKB resources */
    public void setResourcesIkbSelected(final List<String> resourcesIkbSelected) { this.resourcesIkbSelected = new ArrayList<>(resourcesIkbSelected); }

    /** @return the selectable IKB resources */
    public List<SelectItem> getAvailableResourcesIkb() {
        if (availableResourcesIkb==null) {
            availableResourcesIkb = Arrays.asList(
                    new SelectItem(AccessRulesHelper.normalizeResource(InternalKeyBindingRules.DELETE.resource()), super.getEjbcaWebBean().getText(InternalKeyBindingRules.DELETE.getReference())),
                    new SelectItem(AccessRulesHelper.normalizeResource(InternalKeyBindingRules.MODIFY.resource()), super.getEjbcaWebBean().getText(InternalKeyBindingRules.MODIFY.getReference())),
                    new SelectItem(AccessRulesHelper.normalizeResource(InternalKeyBindingRules.VIEW.resource()), super.getEjbcaWebBean().getText(InternalKeyBindingRules.VIEW.getReference()))
                    );
            super.sortSelectItemsByLabel(availableResourcesIkb);
            // Disable the selections what it not allowed by current template
            for (final SelectItem selectItem : availableResourcesIkb) {
                if (!AccessRulesHelper.hasAccessToResource(getAccessRulesTemplate().getAccessRules(), String.valueOf(selectItem.getValue()))) {
                    selectItem.setDisabled(true);
                }
            }
        }
        return availableResourcesIkb;
    }

    /** @return true if the Other rule selection box should be modifiable */
    public boolean isRenderResourcesOtherSelection() {
        return !isAccessRulesTemplateCustom() && !isAccessRulesTemplateSuperAdmin();
    }

    /** @return the currently selected Other resources */
    public List<String> getResourcesOtherSelected() { return resourcesOtherSelected; }
    /** Set the currently selected Other resources */
    public void setResourcesOtherSelected(final List<String> resourcesOtherSelected) { this.resourcesOtherSelected = new ArrayList<>(resourcesOtherSelected); }

    /** @return the selectable Other resources */
    public List<SelectItem> getAvailableResourcesOther() {
        if (availableResourcesOther==null) {
            availableResourcesOther = new ArrayList<>();
            availableResourcesOther.add(new SelectItem(AccessRulesHelper.normalizeResource(AuditLogRules.VIEW.resource()), super.getEjbcaWebBean().getText("VIEWAUDITLOG")));
            if (isEnabledIssueHardwareTokens()) {
                availableResourcesOther.add(new SelectItem(AccessRulesHelper.normalizeResource(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS), super.getEjbcaWebBean().getText("ISSUEHARDTOKENS")));
            }
            super.sortSelectItemsByLabel(availableResourcesOther);
            // Disable the selections what it not allowed by current template
            for (final SelectItem selectItem : availableResourcesOther) {
                if (!AccessRulesHelper.hasAccessToResource(getAccessRulesTemplate().getAccessRules(), String.valueOf(selectItem.getValue()))) {
                    selectItem.setDisabled(true);
                }
            }
        }
        return availableResourcesOther;
    }

    /** @return true if this installation is configured to use EndEntityProfileLimitations */
    private boolean isEnableEndEntityProfileLimitations() {
        return super.getEjbcaWebBean().getGlobalConfiguration().getEnableEndEntityProfileLimitations();
    }

    /** @return true if this installation is configured to issue hardware tokens */
    private boolean isEnabledIssueHardwareTokens() {
        return super.getEjbcaWebBean().getGlobalConfiguration().getIssueHardwareTokens();
    }

    /** @return true if this installation is configured to perform key recovery */
    private boolean isEnabledKeyRecovery() {
        return super.getEjbcaWebBean().getGlobalConfiguration().getEnableKeyRecovery();
    }

    /** Invoked by the user to save the current selection in Basic mode */
    public void actionSaveAccessRules() {
        // Add access rules from template that are not user configurable
        final HashMap<String,Boolean> newAccessRules = new HashMap<>(getAccessRulesTemplate().getAccessRules());
        filterOutSelectItems(newAccessRules, getAvailableResourcesCa());
        filterOutSelectItems(newAccessRules, getAvailableResourcesEe());
        filterOutSelectItems(newAccessRules, getAvailableResourcesEep());
        filterOutSelectItems(newAccessRules, getAvailableResourcesKeyValidators());
        filterOutSelectItems(newAccessRules, getAvailableResourcesIkb());
        filterOutSelectItems(newAccessRules, getAvailableResourcesOther());
        // Add access rules selected by the user
        for (final String resource : getResourcesCaSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        for (final String resource : getResourcesEeSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        for (final String resource : getResourcesEepSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        if (isEnableEndEntityProfileLimitations()) {
            /*
             * To be authorized to an EEP, the authentication token needs to be authorized to both
             *  '/ra_functionality/some_function/'
             *  '/endentityprofilesrules/<eepId>/some_function/'
             *
             * So here in basic mode, we simply allow '/endentityprofilesrules/<eepId>/' and rely
             * on the '/ra_functionality/' sub-rules to limit functions.
             *
             * Long story short: Do nothing here.
             */
        }
        for (final String resource : getResourcesKeyValidatorsSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        for (final String resource : getResourcesIkbSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        for (final String resource : getResourcesOtherSelected()) {
            newAccessRules.put(resource, Role.STATE_ALLOW);
        }
        // Replace access rules and persist
        final Role role = getRole();
        role.getAccessRules().clear();
        role.getAccessRules().putAll(newAccessRules);
        try {
            this.role = roleSession.persistRole(getAdmin(), role);
            super.addGlobalMessage(FacesMessage.SEVERITY_INFO, "ACCESSRULES_INFO_SAVED");
        } catch (RoleExistsException e) {
            throw new IllegalStateException(e);
        } catch (AuthorizationDeniedException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ACCESSRULES_ERROR_UNAUTH", e.getMessage());
        } finally {
            nonAjaxPostRedirectGet();
        }
    }

    /** Remove the resources of the SelectItem values from the access rule map if present */
    private void filterOutSelectItems(final HashMap<String, Boolean> newAccessRules, final List<SelectItem> selectItems) {
        for (final SelectItem selectItem : selectItems) {
            final String selectedResource = String.valueOf(selectItem.getValue());
            final Iterator<Map.Entry<String, Boolean>> iter = newAccessRules.entrySet().iterator();
            while (iter.hasNext()) {
                final Map.Entry<String, Boolean> accessRuleEntry = iter.next();
                final boolean allowed = accessRuleEntry.getValue();
                final String rule = accessRuleEntry.getKey();
                if (allowed && (rule.equals(selectedResource) || rule.startsWith(selectedResource))) {
                    iter.remove();
                }
            }
        }
    }

    /** @return a normalized, minimized and sorted list of access rules that is set to ALLOW or DENY */
    public List<AccessRuleItem> getAccessRules() {
        final List<AccessRuleItem> ret = new ArrayList<>();
        for (final AccessRuleItem accessRuleItem : getAuthorizedAccessRuleItems()) {
            if (!AccessRuleState.UNDEFINED.name().equals(accessRuleItem.getState())) {
                ret.add(accessRuleItem);
            }
        }
        Collections.sort(ret);
        return ret;
    }

    /** @return the advanced mode list of access rule collections  */
    public List<AccessRuleCollection> getAuthorizedResourcesByCategory() {
        final Map<String, AccessRuleCollection> categoryToAccessRuleCollectionMap = new LinkedHashMap<>();
        for (final AccessRuleItem accessRuleItem : getAuthorizedAccessRuleItems()) {
            final String category = accessRuleItem.getCategory();
            AccessRuleCollection accessRuleCollection = categoryToAccessRuleCollectionMap.get(category);
            if (accessRuleCollection==null) {
                accessRuleCollection = new AccessRuleCollection(category, new ArrayList<AccessRuleItem>());
                categoryToAccessRuleCollectionMap.put(category, accessRuleCollection);
            }
            accessRuleCollection.getCollection().add(accessRuleItem);
        }
        for (final AccessRuleCollection accessRuleCollection : categoryToAccessRuleCollectionMap.values()) {
            Collections.sort(accessRuleCollection.getCollection());
        }
        return new ArrayList<>(categoryToAccessRuleCollectionMap.values());
    }

    /** @return the advanced mode list of all authorized access rule items */
    private List<AccessRuleItem> getAuthorizedAccessRuleItems() {
        if (authorizedAccessRuleItems==null) {
            final List<AccessRuleItem> allAccessRuleItems = getAllAccessRuleItems();
            final LinkedHashMap<String, Boolean> rolesAccesssRules = getRole().getAccessRules();
            AccessRulesHelper.minimizeAccessRules(rolesAccesssRules);
            for (final AccessRuleItem accessRuleItem : new ArrayList<>(allAccessRuleItems)) {
                if (authorizationSession.isAuthorizedNoLogging(getAdmin(), accessRuleItem.getResource())) {
                    // Check current Role' state of this rule
                    accessRuleItem.setState(AccessRuleState.toAccessRuleState(rolesAccesssRules.get(accessRuleItem.getResource())).name());
                } else {
                    // Note that for EEPs you are only "really" authorized to it if you also are authorized to all the CAs in it
                    // Similar goes for UserDataSources which is super-inefficient to check..
                    // BUT if the current admin is authorized to a rule he is also authorized to give the same access to others
                    allAccessRuleItems.remove(accessRuleItem);
                }
            }
            authorizedAccessRuleItems = allAccessRuleItems;
        }
        return authorizedAccessRuleItems;
    }

    /** @return the advanced mode list of all access rule items without any state */
    private List<AccessRuleItem> getAllAccessRuleItems() {
        final List<AccessRuleItem> allAccessRuleItem = new ArrayList<>();
        final Map<String, Map<String,String>> categorizedAccessRules = authorizationSystemSession.getAllResourceAndResourceNamesByCategory();
        for (final Entry<String,Map<String,String>> categoryEntry : categorizedAccessRules.entrySet()) {
            for (final Entry<String,String> entry : categoryEntry.getValue().entrySet()) {
                allAccessRuleItem.add(new AccessRuleItem(categoryEntry.getKey(), entry.getKey(), entry.getValue()));
            }
        }
        return allAccessRuleItem;
    }

    /** @return a viewable list of the possible values for a access rule */
    public List<SelectItem> getAvailableAccessRuleStates() {
        if (availableAccessRuleStates.isEmpty()) {
            availableAccessRuleStates.add(new SelectItem(AccessRuleState.ALLOW.name(), super.getEjbcaWebBean().getText("ACCESSRULES_STATE_"+AccessRuleState.ALLOW.name())));
            availableAccessRuleStates.add(new SelectItem(AccessRuleState.DENY.name(), super.getEjbcaWebBean().getText("ACCESSRULES_STATE_"+AccessRuleState.DENY.name())));
            availableAccessRuleStates.add(new SelectItem(AccessRuleState.UNDEFINED.name(), super.getEjbcaWebBean().getText("ACCESSRULES_STATE_"+AccessRuleState.UNDEFINED.name())));
        }
        return availableAccessRuleStates;
    }

    /** @return a viewable list of the possible values for a access rule */
    public List<SelectItem> getAvailableAccessRuleStatesRoot() {
        final List<SelectItem> result = new ArrayList<>();
        result.add(new SelectItem(AccessRuleState.ALLOW.name(), getEjbcaWebBean().getText("ACCESSRULES_STATE_"+AccessRuleState.ALLOW.name())));
        result.add(new SelectItem(AccessRuleState.DENY.name(), getEjbcaWebBean().getText("ACCESSRULES_STATE_"+AccessRuleState.DENY.name()), null, true));
        result.add(new SelectItem(AccessRuleState.UNDEFINED.name(), getEjbcaWebBean().getText("ACCESSRULES_STATE_"+AccessRuleState.UNDEFINED.name() + "_ROOT")));
        return result;
    }

    /** Invoked by the admin when saving access rules in advanced mode. */
    public void actionSaveAccessRulesAdvanced() {
        final Role role = getRole();
        final LinkedHashMap<String, Boolean> accessRules = role.getAccessRules();
        accessRules.clear();
        for (final AccessRuleItem accessRuleItem : authorizedAccessRuleItems) {
            if (!AccessRuleState.UNDEFINED.equals(accessRuleItem.getStateEnum())) {
                accessRules.put(accessRuleItem.getResource(), AccessRuleState.ALLOW.equals(accessRuleItem.getStateEnum()));
            }
        }
        final int numberOfRulesBeforeSave = accessRules.size();
        try {
            this.role = roleSession.persistRole(getAdmin(), role);
            final int numberOfRedundantRules = numberOfRulesBeforeSave-role.getAccessRules().size();
            if (numberOfRedundantRules==0) {
                super.addGlobalMessage(FacesMessage.SEVERITY_INFO, "ACCESSRULES_INFO_SAVED");
            } else {
                super.addGlobalMessage(FacesMessage.SEVERITY_INFO, "ACCESSRULES_INFO_SAVED_MIN", numberOfRedundantRules);
            }
        } catch (RoleExistsException e) {
            throw new IllegalStateException(e);
        } catch (AuthorizationDeniedException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ACCESSRULES_ERROR_UNAUTH", e.getMessage());
        } finally {
            nonAjaxPostRedirectGet();
        }
        authorizedAccessRuleItems = null;
    }
}
