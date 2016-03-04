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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;

import javax.faces.component.html.HtmlSelectOneMenu;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.authorization.AccessRuleTemplate;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.BasicAccessRuleSet;
import org.ejbca.core.model.authorization.BasicAccessRuleSetDecoder;
import org.ejbca.core.model.authorization.BasicAccessRuleSetEncoder;
import org.ejbca.core.model.authorization.DefaultRoles;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.AuthorizationDataHandler;

/**
 * Managed bean for editing administrative privileges.
 * 
 * @version $Id$
 */
public class RolesManagedBean extends BaseManagedBean {

    private static final long serialVersionUID = 1227489070299372101L;

    private static final Logger log = Logger.getLogger(RolesManagedBean.class);

    private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
    private BasicAccessRuleSetEncoder basicAccessRuleSetEncoderCache = null;

    private DefaultRoles currentRoleTemplate = null;
    private List<Integer> currentCAs = null;
    private List<Integer> currentEndEntityProfiles = null;
    private List<Integer> currentOtherRules = null;
    private List<Integer> currentEndEntityRules = null;
    private List<String> currentInternalKeybindingRules = null;
    
    
    private String currentRoleName = null;
    private RoleData currentRole = null;
    private String matchCaId = null;
    
    private HtmlSelectOneMenu matchWithMenu;
    
    private List<SelectItem> matchWithItems;
    
    private AccessMatchType matchType;
   
    private String matchValue = null;

    private String newRoleName = "new";

    private Map<String, List<AccessRuleData>> allRulesViewCache = null;
    
    // Simple from backing
    public String getNewRoleName() {
        return this.newRoleName;
    }

    public void setNewRoleName(String newRoleName) {
        this.newRoleName = newRoleName;
    }
    
    /**
     * 
     * @param rule
     * @param isRecursive
     * @return true if the currently edited role has access to a rule. 
     */
    public boolean hasAccessToRule(String rule, boolean isRecursive) {
        if(currentRole == null) {
            return false;
        } else {
            return currentRole.hasAccessToRule(rule, isRecursive);
        }
    }

    /**
     * Returns if admin is authorized to rule, without logging "accessControlSession.isAuthorizedNoLogging"
     * @param rule
     * @param isRecursive
     * @return true if the current admin is authorized to a rule
     */
    public boolean isAuthorizedToRule(String rule, boolean isRecursive) {
        AccessControlSessionLocal accessControlSession = ejbLocalHelper.getAccessControlSession();
        return accessControlSession.isAuthorizedNoLogging(getAdmin(), isRecursive, rule);
    }
    
    /** @return a List of all roles, excepting ones that refer to CA's which the current role doesn't have access to. */
    public List<RoleData> getRoles() {
        List<RoleData> roles = new ArrayList<RoleData>();
        RoleAccessSessionLocal roleAccessSession = getEjbcaWebBean().getEjb().getRoleAccessSession();
        CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
        roleLoop: for(RoleData role : roleAccessSession.getAllRoles()) {
            // Firstly, make sure that authentication token authorized for all access user aspects in role, by checking against the CA that produced them.
            for (AccessUserAspectData accessUserAspect : role.getAccessUsers().values()) {
                if (!caSession.authorizedToCANoLogging(getAdmin(), accessUserAspect.getCaId())) {
                    continue roleLoop;
                }
            }
            // Secondly, walk through all CAs and make sure that there are no differences. 
            for (Integer caId : caSession.getAllCaIds()) {
                if(!caSession.authorizedToCANoLogging(getAdmin(), caId) && role.hasAccessToRule(StandardRules.CAACCESS.resource() + caId)) {
                    continue roleLoop;
                }
            }
            roles.add(role);
        }
        Collections.sort(roles);
        return roles;
    }

    /** Renames a role */
    public void renameRole() {
        String newRoleName = getNewRoleName();
        try {
            getAuthorizationDataHandler().renameRole(getCurrentRole(), newRoleName);
            setCurrentRole(newRoleName);
        } catch (RoleExistsException e) {
            addErrorMessage("ROLEEXISTS");
        } catch (AuthorizationDeniedException e) {
            addErrorMessage("AUTHORIZATIONDENIED");
        }
    }

    /**
     * Removes a role
     * 
     * @throws RoleNotFoundException
     * 
     */
    public void deleteRole() throws RoleNotFoundException {
        try {
            getAuthorizationDataHandler().removeRole(getCurrentRole());
        } catch (AuthorizationDeniedException e) {
            addErrorMessage("AUTHORIZATIONDENIED");
        }
    }

    /** Adds a new role */
    public void addRole() {
        try {
            getAuthorizationDataHandler().addRole(getNewRoleName());
        } catch (RoleExistsException e) {
            addErrorMessage("ROLEEXISTS");
        } catch (AuthorizationDeniedException e) {
            addErrorMessage("AUTHORIZATIONDENIED");
        }
    }

    /** @return the BasicAccessRuleSetEncoder for the current role in a list */
    public BasicAccessRuleSetEncoder getBasicRuleSetForEach() {
        return getBasicRuleSetInternal(getCurrentRoleObjectForEach());
    }

    /** @return a List of (SelectItem<String, String>) authorized CA */
    public List<SelectItem> getAvailableCas() {
        List<SelectItem> list = new ArrayList<SelectItem>();
        Collection<Integer> availableCAs = getBasicRuleSet().getAvailableCAs(); // All the CAs (and no 'All' flag)
        Map<String, Integer> cas = getEjbcaWebBean().getInformationMemory().getAllCANames();
        for (String caName : cas.keySet()) {
            Integer caId = cas.get(caName);
            if (availableCAs.contains(caId)) {
                list.add(new SelectItem(caId.toString(), caName));
            }
        }
        return list;
    }

    public List<SelectItem> getTokenTypeItems() {
        List<SelectItem> list = new ArrayList<SelectItem>();
        Iterator<String> tokenTypeIterator =  AccessMatchValueReverseLookupRegistry.INSTANCE.getAllTokenTypes().iterator();
        while(tokenTypeIterator.hasNext()) {
            list.add(new SelectItem(tokenTypeIterator.next()));
        }
        return list;
     }
    
    /** @return a viewable list of 'match with'-texts 
     * @throws IllegalAccessException if the class defined by currentAccessMatchValue doesn't have a public constructor.
     * @throws InstantiationException if the class defined by currentAccessMatchValue can't be instantiated
     */
    public List<SelectItem> getMatchWithItems() throws InstantiationException, IllegalAccessException {
        //Lazy initialization
        if (matchWithItems == null) {
            matchWithItems = new ArrayList<SelectItem>();
            List<String> tokenTypes = new ArrayList<String>(AccessMatchValueReverseLookupRegistry.INSTANCE.getAllTokenTypes());
            Collections.sort(tokenTypes);
            for (String tokenType : tokenTypes) {             
                List<AccessMatchValue> accessMatchValues = new ArrayList<AccessMatchValue>(AccessMatchValueReverseLookupRegistry.INSTANCE
                        .getNameLookupRegistryForTokenType(tokenType).values());
                Set<AccessMatchValue> treeSet = new TreeSet<AccessMatchValue>();
                treeSet.addAll(accessMatchValues);
                for (AccessMatchValue current : treeSet) {
                    matchWithItems.add(new SelectItem(tokenType + ":" + current.name(), 
                            getEjbcaWebBean().getText(tokenType) + ": " + getEjbcaWebBean().getText(current.name())));
                }
            }
        }
       
        return matchWithItems;
    }

    /** @return a viewable list of 'match type'-texts */
    public List<SelectItem> getMatchTypeTexts() {
        List<SelectItem> list = new ArrayList<SelectItem>();
        for (AccessMatchType current : AccessMatchType.values()) {
            list.add(new SelectItem(current, getEjbcaWebBean().getText(current.toString())));
        }
        return list;
    }

    public Map<String, Integer> getAccessMatchValuesAsMap() {
        Map<String, Integer> result = new HashMap<String, Integer>();
        for (String tokenType : AccessMatchValueReverseLookupRegistry.INSTANCE.getAllTokenTypes()) {
            for (AccessMatchValue value : AccessMatchValueReverseLookupRegistry.INSTANCE.getNameLookupRegistryForTokenType(tokenType).values()) {
                result.put(tokenType + ":" + value.name(), value.getNumericValue());
            }
        }
        return result;
    }

    // Simple form backing
    public String getMatchCaId() {
        return matchCaId;
    }
    
    public void setMatchCaId(String matchCaId) {
        this.matchCaId = matchCaId;
    }

    public HtmlSelectOneMenu getMatchWithMenu() {
        if(matchWithMenu == null) {
            matchWithMenu = new HtmlSelectOneMenu();
        }
        if(matchWithMenu.getValue() == null) {
            matchWithMenu.setValue(getDefaultMatchWith());
        }
        return matchWithMenu;
    }

    public void setMatchWithMenu(HtmlSelectOneMenu matchWithMenu) {
        this.matchWithMenu = matchWithMenu;
    }

    public AccessMatchType getMatchType() {
        if(matchType == null) {
            //Default value
            setMatchType(AccessMatchType.TYPE_EQUALCASE);
        }
        return matchType;
    }

    public void setMatchType(AccessMatchType matchType) {
        this.matchType = matchType;
    }

    public String getMatchValue() {
        return matchValue;
    }

    public void setMatchValue(String matchValue) {
        this.matchValue = matchValue;
    }

    /**
     * Adds an admin to the current role.
     * 
     * @throws RoleNotFoundException
     */
    public void addAdmin() throws RoleNotFoundException {
        String[] matchWithMenuItems = ((String) matchWithMenu.getValue()).split(":");
        AccessMatchValue matchWith = AccessMatchValueReverseLookupRegistry.INSTANCE.lookupMatchValueFromTokenTypeAndName(matchWithMenuItems[0],
                matchWithMenuItems[1]);
        AccessMatchType matchType = getMatchType();
        String matchValue = getMatchValue();
        if (matchValue == null || "".equals(matchValue)) {
            addErrorMessage("MATCHVALUEREQUIRED");
            return;
        }
        int caid = Integer.parseInt(getMatchCaId());
        AccessUserAspectData adminEntity = new AccessUserAspectData(getCurrentRoleObject().getRoleName(), caid, matchWith, matchType,
                matchValue);
        // TODO: Check if adminentity exists and add a nice errormessage instead of being silent
        Collection<AccessUserAspectData> adminEntities = new ArrayList<AccessUserAspectData>();
        adminEntities.add(adminEntity);
        try {
            getAuthorizationDataHandler().addAdminEntities(getCurrentRoleObject(), adminEntities);
        } catch (AuthorizationDeniedException e) {
            addErrorMessage("AUTHORIZATIONDENIED");
        }
    }

    /**
     * Removes an admin from the current role.
     * 
     * @throws RoleNotFoundException
     */
    public void deleteAdmin() throws RoleNotFoundException {
        final String primaryKey = (String) FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("primaryKey");
        if (primaryKey==null) {
            addErrorMessage("ACCESSUSERASPECT_UNKNOWN");
            return;
        }
        final int pk;
        try {
            pk = Integer.parseInt(primaryKey);
        } catch (NumberFormatException e) {
            addErrorMessage("ACCESSUSERASPECT_UNKNOWN");
            return;
        }
        final AccessUserAspectData adminEntity = getAuthorizationDataHandler().getRole((getCurrentRole())).getAccessUsers().get(pk);
        if (adminEntity==null) {
            addErrorMessage("ACCESSUSERASPECT_UNKNOWN");
            return;
        }
        Collection<AccessUserAspectData> adminEntities = new ArrayList<AccessUserAspectData>();
        adminEntities.add(adminEntity);
        try {
            getAuthorizationDataHandler().removeAdminEntities(getCurrentRoleObject(), adminEntities);
        } catch (AuthorizationDeniedException e) {
            addErrorMessage("AUTHORIZATIONDENIED");
        }
    }

    /** @return the current role for the current row in the datatable */
    private RoleData getCurrentRoleObjectForEach() {
        String roleName = ((RoleData) FacesContext.getCurrentInstance().getExternalContext().getRequestMap().get("role")).getRoleName();
        return getAuthorizationDataHandler().getRole(roleName);
    }

    /** @return the administrators for the current role */
    public Collection<AccessUserAspectData> getAdmins() {
        List<AccessUserAspectData> list = new ArrayList<AccessUserAspectData>();
        list.addAll(getAuthorizationDataHandler().getRole((getCurrentRole())).getAccessUsers().values());
        Collections.sort(list);
        return list;
    }

    public String getDefaultMatchWith() {
        String defaultToken = X509CertificateAuthenticationToken.TOKEN_TYPE;
        return defaultToken + ":" + AccessMatchValueReverseLookupRegistry.INSTANCE.getDefaultValueForTokenType(defaultToken);
    }
    
    /** @return the name of the CA that has issued the certificate for the admin in the current row of the datatable */
    public String getIssuingCA() {
        AccessUserAspectData adminEntity = getAdminForEach();
        String caName = (String) ejbLocalHelper.getCaSession().getCAIdToNameMap().get(adminEntity.getCaId());
        if (caName == null) {
            caName = "Unknown CA with hash " + adminEntity.getCaId();
        }
        if (AccessMatchValueReverseLookupRegistry.INSTANCE.getDefaultValueForTokenType(adminEntity.getTokenType()).isIssuedByCa()) {
            return caName;
        } else {
            return "";
        }
    }

    public String getAdminsTokenType() {
        AccessUserAspectData userAspect = getAdminForEach();
        return getEjbcaWebBean().getText(userAspect.getTokenType());
    }
    
    /** @return the 'match with'-text for the admin in the current row of the datatable */
    public String getAdminsMatchWith() {
        AccessUserAspectData userAspect = getAdminForEach();
        return getAdminsTokenType()
                + ":"
                + getEjbcaWebBean().getText(
                        AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(userAspect.getTokenType(), userAspect.getMatchWith())
                                .name());
    }

    /** @return the 'match type'-text for the admin in the current row of the datatable */
    public String getAdminsMatchType() {
        AccessUserAspectData userAspect = getAdminForEach();
        return "" + getEjbcaWebBean().getText(userAspect.getMatchTypeAsType().toString());
    }

    /** @return the AdminEntity object for the current row in the datatable */
    private AccessUserAspectData getAdminForEach() {
        return (AccessUserAspectData) FacesContext.getCurrentInstance().getExternalContext().getRequestMap().get("admin");
    }

    //
    // Edit basic access rules (mostly used by editbasicaccessrules.jsp)
    //

    // Stores the value from request, but always reads the value directly from the saved data
    public String getCurrentRoleTemplate() {      
        final RoleData currentRole = getCurrentRoleObject();
        final String roleName = currentRole.getRoleName();
        //Strip out all external rules until only the template remains.
        Collection<AccessRuleTemplate> externalRules = new ArrayList<AccessRuleTemplate>();
        externalRules.addAll(BasicAccessRuleSetDecoder.getCaRules(roleName, getBasicRuleSet().getCurrentCAs()));
        externalRules.addAll(BasicAccessRuleSetDecoder.getEndEntityRules(getBasicRuleSet().getCurrentEndEntityProfiles(), getBasicRuleSet().getCurrentEndEntityRules()));
        externalRules.addAll(BasicAccessRuleSetDecoder.getOtherRules(roleName, getBasicRuleSet().getCurrentOtherRules()));        
        DefaultRoles result = DefaultRoles.identifyFromRuleSet(currentRole.getAccessRules().values(), externalRules);        
        return result.getName();
    }

    public void setCurrentRoleTemplate(String currentRoleTemplate) {
        this.currentRoleTemplate = DefaultRoles.getDefaultRoleFromName(currentRoleTemplate);
    }

    public List<String> getCurrentCAs() {
        return integerSetToStringList(getBasicRuleSet().getCurrentCAs());
    }

    public void setCurrentCAs(List<String> currentCAs) {
        this.currentCAs = stringListToIntegerList(currentCAs);
    }

    public List<String> getCurrentEndEntityProfiles() {
        return integerSetToStringList(getBasicRuleSet().getCurrentEndEntityProfiles());
    }

    public void setCurrentEndEntityProfiles(List<String> currentEndEntityProfiles) {
        this.currentEndEntityProfiles = stringListToIntegerList(currentEndEntityProfiles);
    }

    public List<String> getCurrentOtherRules() {
        return integerSetToStringList(getBasicRuleSet().getCurrentOtherRules());
    }

    public void setCurrentOtherRules(List<String> currentOtherRules) {
        this.currentOtherRules = stringListToIntegerList(currentOtherRules);
    }

    public List<String> getCurrentEndEntityRules() {
        return integerSetToStringList(getBasicRuleSet().getCurrentEndEntityRules());
    }
    
    public List<String> getCurrentInternalKeyBindingRules() {
        return getBasicRuleSet().getCurrentInternalKeyBindingRules();
    }

    public void setCurrentInternalKeyBindingRules(List<String> internalKeyBindingRules) {
        this.currentInternalKeybindingRules = internalKeyBindingRules;
    }
    
    public void setCurrentEndEntityRules(List<String> currentEndEntityRules) {
        this.currentEndEntityRules = stringListToIntegerList(currentEndEntityRules);
    }

    /** @return a cached BasicAccessRuleSet */
    public BasicAccessRuleSetEncoder getBasicRuleSet() {
        if (basicAccessRuleSetEncoderCache == null) {
            basicAccessRuleSetEncoderCache = getBasicRuleSetInternal(getCurrentRoleObject());
        }
        return basicAccessRuleSetEncoderCache;
    }

    /** @return the public constants of BasicAccessRuleSet as a Map */
    public Map<String, Object> getBasicAccessRuleSetConstants() {
        return getPublicConstantsAsMap(BasicAccessRuleSet.class);
    }

    /** @return the available admin roles as a Collection<SelectItem> */
    public Collection<SelectItem> getAvailableRoles() {
        Collection<SelectItem> list = new ArrayList<SelectItem>();
        for (String currentRole : getBasicRuleSet().getAvailableRoles()) {
            list.add(new SelectItem(currentRole, getEjbcaWebBean().getText(currentRole)));
        }
        return list;
    }

    /** @return the available cas as a Collection<SelectItem> */
    public Collection<SelectItem> getAvailableCasAndAll() {
        List<SelectItem> cas = getAvailableCas();

        if (getAuthorizationDataHandler().isAuthorizedNoLog(getAdmin(), StandardRules.CAACCESSBASE.resource())) {
            cas.add(0, new SelectItem(String.valueOf(BasicAccessRuleSet.CA_ALL), getEjbcaWebBean().getText("ALL")));
        }

        return cas;
    }

    /** @return the available end entity rules as a Collection<SelectItem> */
    public Collection<SelectItem> getAvailableEndEntityRules() {
        Collection<SelectItem> list = new ArrayList<SelectItem>();
        for (Integer currentRule : (Collection<Integer>) getBasicRuleSet().getAvailableEndEntityRules()) {
            list.add(new SelectItem(currentRule, getEjbcaWebBean().getText(BasicAccessRuleSet.getEndEntityRuleText(currentRule))));
        }
        return list;
    }

    /** @return the available end entity profile rules as a Collection<SelectItem> */
    public Collection<SelectItem> getAvailableEndEntityProfiles() {
        Collection<SelectItem> list = new ArrayList<SelectItem>();
        for (Integer currentProfile : (Collection<Integer>) getBasicRuleSet().getAvailableEndEntityProfiles()) {
            if (currentProfile == BasicAccessRuleSet.ENDENTITYPROFILE_ALL) {
                list.add(new SelectItem(currentProfile, getEjbcaWebBean().getText("ALL")));
            } else {
                list.add(new SelectItem(currentProfile, ejbLocalHelper.getEndEntityProfileSession().getEndEntityProfileName(currentProfile)));
            }
        }
        return list;
    }

    /** @return the available other access rules as a Collection<SelectItem> */
    public Collection<SelectItem> getAvailableOtherRules() {
        Collection<SelectItem> list = new ArrayList<SelectItem>();
        for (Integer currentRule : (Collection<Integer>) getBasicRuleSet().getAvailableOtherRules()) {
            list.add(new SelectItem(currentRule.toString(), getEjbcaWebBean().getText(BasicAccessRuleSet.OTHERTEXTS[currentRule])));
        }
        return list;
    }

    public List<SelectItem> getAvailableInternalKeyBindingRules() {
        List<SelectItem> list = new ArrayList<SelectItem>();
        for(String rule : getBasicRuleSet().getAvailableInternalKeyBindingRules()) {
            list.add(new SelectItem(rule, getEjbcaWebBean().getText(InternalKeyBindingRules.getFromResource(rule).getReference())));
        }
        return list;
    }
    
    /**
     * Save the current state of the access rules and invalidate caches
     * 
     * @throws RoleNotFoundException if the current role for some reason doesn't exist
     * @throws InvalidRoleTemplateException if rules were added to the role using an invalid template
     */
    public void saveAccessRules() throws RoleNotFoundException, InvalidRoleTemplateException {
        BasicAccessRuleSetDecoder barsd = new BasicAccessRuleSetDecoder(currentRoleTemplate.getName(), currentCAs, currentEndEntityRules,
                currentEndEntityProfiles, currentInternalKeybindingRules, currentOtherRules);
        
        if(currentRoleTemplate.equals(DefaultRoles.CUSTOM.getName())) {
            throw new InvalidRoleTemplateException("Attempting to add rules to a rule using the Custom role template from basic mode is invalid.");
        }
        
        try {
            //Using a map in order to weed out duplicates. 
            Map<Integer, AccessRuleData> rulesToReplaceWith = new HashMap<Integer, AccessRuleData>();
            for (AccessRuleTemplate template : barsd.getCurrentAdvancedRuleSet()) {
                AccessRuleData rule = template.createAccessRuleData(currentRoleName);
                if (!rulesToReplaceWith.containsKey(rule.getPrimaryKey())) {
                    rulesToReplaceWith.put(rule.getPrimaryKey(), rule);
                } else {
                    //Examine if we're trying to submit two rules which aren't the exact same.
                    if (!rule.equals(rulesToReplaceWith.get(rule.getPrimaryKey()))) {
                        throw new IllegalStateException("RolesManagedBean tried to save two overlapping rules (" + rule.getAccessRuleName()
                                + ") with different values.");
                    }
                }
            }
            getAuthorizationDataHandler().replaceAccessRules(getCurrentRole(), rulesToReplaceWith.values());
        } catch (AuthorizationDeniedException e) {
            addErrorMessage("AUTHORIZATIONDENIED");
        }
        basicAccessRuleSetEncoderCache = null; // We want this to be re-read
        getEjbcaWebBean().getInformationMemory().administrativePriviledgesEdited();
    }

    private BasicAccessRuleSetEncoder getBasicRuleSetInternal(RoleData role) {
        GlobalConfiguration globalConfiguration = getEjbcaWebBean().getGlobalConfiguration();
        return new BasicAccessRuleSetEncoder(role.getAccessRules().values(), getAuthorizationDataHandler().getAvailableAccessRulesUncategorized(AccessRulesConstants.CREATE_END_ENTITY),
                globalConfiguration.getIssueHardwareTokens(), globalConfiguration.getEnableKeyRecovery());
    }


    /** @return a cached list of all the available access rules */
    private Map<String, List<AccessRuleData>> getAccessRules() {
        log.trace(">getAccessRules");
        if (allRulesViewCache == null) {
            RoleData role = getCurrentRoleObject();      
            Map<String, Set<String>> redactedRules = getAuthorizationDataHandler()
                    .getRedactedAccessRules(AccessRulesConstants.CREATE_END_ENTITY);
            allRulesViewCache = getCategorizedRuleSet(role, redactedRules);   
        }
        log.trace("<getAccessRules");
        return allRulesViewCache;
    }

    /**
     *  Takes a role and a set of rules, returning map (sorted by category) of all rules, with set states for those rules contained in the role
     * 
     * @param role a Role
     * @param redactedRules a list of all rules, barring unauthorized CAs, CPs, EEPs, CryptoTokens 
     * @return the sought map
     */
    private Map<String, List<AccessRuleData>> getCategorizedRuleSet(RoleData role, Map<String, Set<String>> redactedRules) {
        Map<String, List<AccessRuleData>> result = new LinkedHashMap<String, List<AccessRuleData>>();
        Map<Integer, AccessRuleData> knownRules = role.getAccessRules();
        if (redactedRules != null) {
            for (String category : redactedRules.keySet()) {
                List<AccessRuleData> subset = new ArrayList<AccessRuleData>();
                for (String rule : redactedRules.get(category)) {
                    Integer key = AccessRuleData.generatePrimaryKey(role.getRoleName(), rule);
                    if (!knownRules.containsKey(key)) {
                        // Access rule can not be found, create a new AccessRuleData that we can return
                        subset.add(new AccessRuleData(key.intValue(), rule, AccessRuleState.RULE_NOTUSED, false));
                    } else {
                        subset.add(knownRules.get(key));
                    }
                }
                result.put(category, subset);
            }
        }
        return result;
    }
    
    /** @return a list of lists with access rules and the category name */
    public List<AccessRuleCollection> getAccessRulesCollections() {
        List<AccessRuleCollection> result = new ArrayList<AccessRuleCollection>();
        for(Entry<String, List<AccessRuleData>> entry : getAccessRules().entrySet()) {
            result.add(new AccessRuleCollection(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    /** @return a viewable list of the possible values for a access rule */
    public Collection<SelectItem> getAccessRuleStates() {
        Collection<SelectItem> result = new ArrayList<SelectItem>();
        result.add(new SelectItem(AccessRuleState.RULE_NOTUSED.getDatabaseValue(), getEjbcaWebBean().getText(AccessRuleState.RULE_NOTUSED.getName(), true)));
        result.add(new SelectItem(AccessRuleState.RULE_ACCEPT.getDatabaseValue(), getEjbcaWebBean().getText(AccessRuleState.RULE_ACCEPT.getName(), true)));
        result.add(new SelectItem(AccessRuleState.RULE_DECLINE.getDatabaseValue(), getEjbcaWebBean().getText(AccessRuleState.RULE_DECLINE.getName(), true)));
        return result;
    }

    /**
     * @return a parsed version of the accessrule for the current row in the datatable. CAs, End Entity Profiles and UserDataSources are given their
     *         cleartext name.
     */
    public String getParsedAccessRule() {
        AccessRuleData accessRule = (AccessRuleData) FacesContext.getCurrentInstance().getExternalContext().getRequestMap().get("accessRule");
        String resource = accessRule.getAccessRuleName();
        // Check if it is a profile rule, then replace profile id with profile name.
        Map<Integer, String> profileMap = ejbLocalHelper.getEndEntityProfileSession().getEndEntityProfileIdToNameMap();
        if (resource.startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.ENDENTITYPROFILEPREFIX.length()) {
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX 
                		+ profileMap.get(Integer.parseInt(resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length())));
            } else {
                String tmpString = resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length());
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX
                        + profileMap.get(
                                Integer.parseInt(tmpString.substring(0, tmpString.indexOf('/')))) + tmpString.substring(tmpString.indexOf('/'));
            }
        }
        // Check if it is a CA rule, then replace CA id with CA name.
        if (resource.startsWith(StandardRules.CAACCESS.resource())) {
            Map<Integer, String> caIdToNameMap = ejbLocalHelper.getCaSession().getCAIdToNameMap();
            if (resource.lastIndexOf('/') < StandardRules.CAACCESS.resource().length()) {
                return StandardRules.CAACCESS.resource() + caIdToNameMap.get(Integer.valueOf(resource.substring(StandardRules.CAACCESS.resource().length())));
            } else {
                return StandardRules.CAACCESS.resource()
                        + caIdToNameMap.get(Integer.valueOf(resource.substring(StandardRules.CAACCESS.resource().length(), resource.lastIndexOf('/'))))
                        + resource.substring(resource.lastIndexOf('/'));
            }
        }
        // Check if it is a User Data Source rule, then replace User Data Source id with User Data Source name.
        if (resource.startsWith(AccessRulesConstants.USERDATASOURCEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.USERDATASOURCEPREFIX.length()) {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + ejbLocalHelper.getUserDataSourceSession().getUserDataSourceName(getAdmin(),
                                Integer.parseInt(resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length())));
            } else {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + ejbLocalHelper.getUserDataSourceSession().getUserDataSourceName(getAdmin(),
                                Integer.parseInt(resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length(), resource.lastIndexOf('/'))))
                        + resource.substring(resource.lastIndexOf('/'));
            }
        }
        // Check if it is a CryptoToken rule, then replace CryptoToken id with CryptoToken name.
        if (resource.startsWith(CryptoTokenRules.BASE.resource() + '/')) {
            final int lastIndexOfSlash = resource.lastIndexOf('/');
            try {
                final Integer cryptoTokenId = Integer.valueOf(resource.substring(lastIndexOfSlash+1));
                // Use local invocation without checking authorization, since we 
                final CryptoTokenInfo cryptoTokenInfo = ejbLocalHelper.getCryptoTokenManagementSession().getCryptoTokenInfo(cryptoTokenId);
                if (cryptoTokenInfo != null) {
                    return resource.substring(0, lastIndexOfSlash+1) + cryptoTokenInfo.getName();
                }
            } catch (NumberFormatException e) {
                // Ignore.. we only want to convert the ones where the last section is a number
            }
            return resource;
        }
        return resource;
    }

    /**
     * Save the current state of the access rules and invalidate caches
     * 
     * @throws RoleNotFoundException
     */
    public void saveAdvancedAccessRules() throws RoleNotFoundException {
        log.info("Trying to replace access rules..");
        Collection<AccessRuleData> allRules = new ArrayList<AccessRuleData>();
        Collection<AccessRuleData> toReplace = new ArrayList<AccessRuleData>();
        List<AccessRuleData> toRemove = new ArrayList<AccessRuleData>();
        for (Entry<String, List<AccessRuleData>> entry : getAccessRules().entrySet()) {
            allRules.addAll(entry.getValue());
        }
        // Remove all access rules marked as UNUSED and replace the others
        for (AccessRuleData ar : allRules) {
            if (ar.getInternalState() == AccessRuleState.RULE_NOTUSED) {
                toRemove.add(ar);
            } else {
                toReplace.add(ar);
            }
        }
        try {
            getAuthorizationDataHandler().removeAccessRules(currentRoleName, toRemove);
            getAuthorizationDataHandler().replaceAccessRules(currentRoleName, toReplace);
        } catch (AuthorizationDeniedException e) {
            addErrorMessage("AUTHORIZATIONDENIED");
        }
        allRulesViewCache = null; // We want this to be re-read
        basicAccessRuleSetEncoderCache = null; // We want this to be re-read
        getEjbcaWebBean().getInformationMemory().administrativePriviledgesEdited();
    }

    /** Invalidates local cache */
    public void restoreAdvancedAccessRules() {
        allRulesViewCache = null; // We want this to be re-read
    }

    //
    // Methods used by several pages
    //

    /** @return the name of current role sent with POST, GET or injected through the backing value */
    public String getCurrentRole() {
        // Did we get the Role passed as f:param to this page or as a GET parameter?
        String current = currentRoleName;
        // Try reading it from the form POST
        final String FIELDNAME = "currentRole";
        final String[] FORMNAMES = { "currentGroupList", "adminListForm", "basicRules", "accessRulesForm" };
        for (String key : FORMNAMES) {
            if (current != null) {
                break;
            }
            current = getRequestParameter(key + ":" + FIELDNAME);
        }
        return current;
    }

    /** @return the current role sent with POST, GET or injected through the backing value */
    public RoleData getCurrentRoleObject() {
        return getAuthorizationDataHandler().getRole(getCurrentRole());
    }

    /** Setter for current role used were applicable. */
    public void setCurrentRole(String currentRoleName) {
        this.currentRoleName = currentRoleName;
        this.currentRole = ejbLocalHelper.getRoleAccessSession().findRole(currentRoleName);
    }



    /** @return true if logged on administrator is allowed to edit current role */
    public boolean isAuthorizedToEdit() {
        return ejbLocalHelper.getAccessControlSession().isAuthorizedNoLogging(getAdmin(), StandardRules.EDITROLES.resource());
    }
    
    //
    // Helper functions
    //

    private AuthorizationDataHandler getAuthorizationDataHandler() {
        return getEjbcaWebBean().getAuthorizationDataHandler();
    }

    private String getRequestParameter(String key) {
        return (String) FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get(key);
    }

    private static List<String> integerSetToStringList(Set<Integer> hashSet) {
        List<String> stringList = new ArrayList<String>();
        for (Integer item : hashSet) {
            stringList.add(item.toString());
        }
        return stringList;
    }

    private static List<Integer> stringListToIntegerList(List<String> stringList) {
        List<Integer> integerList = new ArrayList<Integer>();
        for (String string : stringList) {
            integerList.add(Integer.parseInt(string));
        }
        return integerList;
    }

    /* Useful for debugging and development..
    private void dumpAllParameters() {
    	Map m = FacesContext.getCurrentInstance().getExternalContext().getRequestMap();
    	Iterator i1 = m.keySet().iterator();
    	String x = "";
    	while (i1.hasNext()) {
    		String key = (String) i1.next();
    		x +=  key + "=" + m.get(key) + " ";
    	}
    	log.info("RequestMap: " + x);
    	Map m2 = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap();
    	Iterator i2 = m2.keySet().iterator();
    	x = "";
    	while (i2.hasNext()) {
    		String key = (String) i2.next();
    		x +=  key + "=" + m2.get(key) + " ";
    	}
    	log.info("RequestParameterMap: " + x);
    }
    */
}
