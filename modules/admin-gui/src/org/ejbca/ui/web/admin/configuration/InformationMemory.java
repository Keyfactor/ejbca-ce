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

/*
 * InformationMemory.java
 *
 * Created on den 14 juli 2003, 14:05
 */

package org.ejbca.ui.web.admin.configuration;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.management.RoleManagementSession;
import org.cesecore.roles.management.RoleManagementSessionLocal;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSession;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSession;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.admin.cainterface.CAAuthorization;
import org.ejbca.ui.web.admin.cainterface.CertificateProfileNameProxy;
import org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization;
import org.ejbca.ui.web.admin.rainterface.EndEntityProfileNameProxy;

/**
 * A class used to improve performance by proxying authorization information about the administrator. It should be used in all jsp interface bean
 * classes.
 * 
 * @version $Id$
 */
public class InformationMemory implements Serializable {

    private static final long serialVersionUID = 2L;
    // Private fields
    private AuthenticationToken administrator;
    // Session Bean interfaces (was *Local originally)
    private CAAdminSession caadminsession;
    private CaSessionLocal casession;
    private EndEntityProfileSession endEntityProfileSession;
    private PublisherSessionLocal publishersession;
    private UserDataSourceSession userdatasourcesession = null;
    private CertificateProfileSession certificateProfileSession;
    private ComplexAccessControlSession complexAccessControlSession;
    private RoleManagementSession roleManagementSession;

    // Memory variables.
    RAAuthorization raauthorization = null;
    CAAuthorization caauthorization = null;
    HardTokenAuthorization hardtokenauthorization = null;

    Map<Integer, String> caidtonamemap = null;
    Map<Integer, HashMap<Integer, List<Integer>>> endentityavailablecas = null;
    Map<Integer, String> publisheridtonamemap = null;

    TreeMap<String, Integer> authRoles = null;
    TreeMap<String, Integer> publishernames = null;
    Map<Integer, String> roldIdMap = null;

    Map<String, Set<String>> authorizedaccessrules = null;

    GlobalConfiguration globalconfiguration = null;
    CmpConfiguration cmpconfiguration = null;
    EndEntityProfileNameProxy endentityprofilenameproxy = null;
    CertificateProfileNameProxy certificateprofilenameproxy = null;

    /** Creates a new instance of ProfileNameProxy */
    public InformationMemory(AuthenticationToken administrator, CAAdminSession caadminsession, CaSessionLocal caSession, AccessControlSessionLocal authorizationsession,
            ComplexAccessControlSessionLocal complexAccessControlSession, EndEntityProfileSession endEntityProfileSession,
            HardTokenSession hardtokensession, PublisherSessionLocal publishersession, UserDataSourceSession userdatasourcesession,
            CertificateProfileSession certificateProfileSession, GlobalConfigurationSession globalConfigurationSession, RoleManagementSessionLocal roleManagementSession,
            GlobalConfiguration globalconfiguration, CmpConfiguration cmpconfig) {
        this.caadminsession = caadminsession;
        this.casession = caSession;
        this.administrator = administrator;
        this.endEntityProfileSession = endEntityProfileSession;
        this.publishersession = publishersession;
        this.userdatasourcesession = userdatasourcesession;
        this.globalconfiguration = globalconfiguration;
        this.cmpconfiguration = cmpconfig;
        this.certificateProfileSession = certificateProfileSession;
        this.raauthorization = new RAAuthorization(administrator, globalConfigurationSession, authorizationsession, complexAccessControlSession,
                caSession, endEntityProfileSession);
        this.caauthorization = new CAAuthorization(administrator, caSession, certificateProfileSession);
        this.hardtokenauthorization = new HardTokenAuthorization(administrator, hardtokensession, authorizationsession, roleManagementSession);
        this.complexAccessControlSession = complexAccessControlSession;
        this.roleManagementSession = roleManagementSession;
    }

    public String getCertificateProfileName(int id) {
        return this.certificateProfileSession.getCertificateProfileName(id);
    }

    /**
     * Returns a Map of CA id (Integer) -> CA name (String).
     */
    public Map<Integer, String> getCAIdToNameMap() {
        if (caidtonamemap == null) {
            caidtonamemap = casession.getCAIdToNameMap();
        }

        return caidtonamemap;
    }

    /**
     * Returns a Map of hard token profile id (Integer) -> hard token profile name (String).
     */
    public Map<Integer, String> getHardTokenProfileIdToNameMap() {
        return this.hardtokenauthorization.getHardTokenProfileIdToNameMap();
    }

    /**
     * Returns authorized end entity profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedEndEntityProfileNames() {
        return this.raauthorization.getAuthorizedEndEntityProfileNames();
    }
    
    /**
     * Returns a list of authorized end-entity profiles ids of profiles with missing CA Ids.
     */
    public List<Integer> getAuthorizedEndEntityProfileIdsWithMissingCAs() {
        return this.raauthorization.getViewAuthorizedEndEntityProfilesWithMissingCAs();
    }

    /**
     * Returns end entity profile names with create rights as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getCreateAuthorizedEndEntityProfileNames() {
        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            return this.raauthorization.getCreateAuthorizedEndEntityProfileNames();
        }
        return this.raauthorization.getAuthorizedEndEntityProfileNames();
    }

    /**
     * Returns end entity profile names with view rights as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getViewAuthorizedEndEntityProfileNames() {
        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            return this.raauthorization.getViewAuthorizedEndEntityProfileNames();
        }
        return this.raauthorization.getAuthorizedEndEntityProfileNames();
    }

    /**
     * Returns authorized end entity certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedEndEntityCertificateProfileNames() {
        return this.caauthorization.getAuthorizedEndEntityCertificateProfileNames(getGlobalConfiguration().getIssueHardwareTokens());
    }

    /**
     * Returns authorized sub CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedSubCACertificateProfileNames() {
        return this.caauthorization.getAuthorizedSubCACertificateProfileNames();
    }

    /**
     * Returns authorized root CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedRootCACertificateProfileNames() {
        return this.caauthorization.getAuthorizedRootCACertificateProfileNames();
    }

    /**
     * Returns authorized CA names as a treemap of name (String) -> id (Integer).
     */
    public Map<String, Integer> getCANames() {
        TreeMap<String, Integer> canames = new TreeMap<String, Integer>();
        HashMap<Integer, String> idtonamemap = casession.getCAIdToNameMap();
        for (Integer id : getAuthorizedCAIds()) {
            canames.put(idtonamemap.get(id), id);
        }
        return canames;
    }
    
    /**
     * Returns a CA names as a treemap of name (String) -> id (Integer). Doesn't include non-active or external CAs.
     */
    public Map<String, Integer> getActiveCANames() {
        TreeMap<String, Integer> canames = new TreeMap<String, Integer>();
        Map<Integer, String> idtonamemap = this.casession.getActiveCAIdToNameMap(administrator);
        for (Integer id : idtonamemap.keySet()) {
            canames.put(idtonamemap.get(id), id);
        }
        return canames;
    }

    
    
    /**
     * Returns a CA names as a treemap of name (String) -> id (Integer). Also includes external CAs
     */
    public TreeMap<String, Integer> getAllCANames() {
        return this.caauthorization.getAllCANames();
    }

    /**
     * Returns a CA names as a treemap of name (String) -> id (Integer). Also includes external CAs
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     */
    public TreeMap<String, Integer> getExternalCAs() throws CADoesntExistsException, AuthorizationDeniedException {
        TreeMap<String, Integer> allcas = this.caauthorization.getAllCANames();
        TreeMap<String, Integer> externalcas = new TreeMap<String, Integer>();
        Iterator<String> itr = allcas.keySet().iterator();
        while(itr.hasNext()) {
            String caname = (String) itr.next();
            CA ca = casession.getCA(administrator, caname);
            if (ca.getStatus() == CAConstants.CA_EXTERNAL) {
                externalcas.put(caname, allcas.get(caname));
            }
        }
        return externalcas;
    }
    
    /**
     * Returns CA authorization string used in userdata queries.
     */
    public String getUserDataQueryCAAuthoorizationString() {
        return this.raauthorization.getCAAuthorizationString();
    }

    /**
     * Returns CA authorization string used in userdata queries.
     */
    public String getUserDataQueryEndEntityProfileAuthorizationString() {
        return this.raauthorization.getEndEntityProfileAuthorizationString(true);
    }

    /**
     * Returns a Collection of Integer containing authorized CA ids.
     */
    public List<Integer> getAuthorizedCAIds() {
        return caauthorization.getAuthorizedCAIds();
    }

    /**
     * Returns the system configuration (GlobalConfiguration).
     */
    public GlobalConfiguration getGlobalConfiguration() {
        return globalconfiguration;
    }
    
    /**
     * returns the CMP configuration (CMPConfiguration)
     */
    public CmpConfiguration getCMPConfiguration() {
        return cmpconfiguration;
    }

    /**
     * Returns the end entity profile name proxy
     */
    public EndEntityProfileNameProxy getEndEntityProfileNameProxy() {
        if (endentityprofilenameproxy == null) {
            endentityprofilenameproxy = new EndEntityProfileNameProxy(endEntityProfileSession);
        }
        return endentityprofilenameproxy;
    }

    /**
     * Returns the end entity profile name proxy
     */
    public CertificateProfileNameProxy getCertificateProfileNameProxy() {
        if (certificateprofilenameproxy == null) {
            certificateprofilenameproxy = new CertificateProfileNameProxy(certificateProfileSession);
        }
        return certificateprofilenameproxy;
    }

    /**
     * Method returning the all available publishers id to name.
     * 
     * @return the publisheridtonamemap (HashMap)
     */
    public Map<Integer, String> getPublisherIdToNameMap() {
        if (publisheridtonamemap == null) {
            publisheridtonamemap = publishersession.getPublisherIdToNameMap();
        }
        return publisheridtonamemap;
    }

    /**
     * Returns all authorized publishers names as a treemap of name (String) -> id (Integer).
     */
    public TreeMap<String, Integer> getAuthorizedPublisherNames() {
        if (publishernames == null) {
            publishernames = new TreeMap<String, Integer>();
            Iterator<Integer> iter = caadminsession.getAuthorizedPublisherIds(administrator).iterator();
            Map<Integer, String> idtonamemap = getPublisherIdToNameMap();
            while (iter.hasNext()) {
                Integer id = iter.next();
                publishernames.put(idtonamemap.get(id), id);
            }
        }
        return publishernames;
    }

    /**
     * Method that calculates the available CAs to an end entity. Used in add/edit end entity pages. It calculates a set of available CAs as an
     * intersection of: - The administrator's authorized CAs, the end entity profile's available CAs and the certificate profile's available CAs.
     * 
     * @param endentityprofileid the EE profile of the end entity
     * @returns a HashMap of CertificateProfileIds mapped to Lists if CA IDs. It returns a set of available CAs per end entity profile.
     */

    public Map<Integer, List<Integer>> getCasAvailableToEndEntity(int endentityprofileid) {
        if (endentityavailablecas == null) {
            endentityavailablecas = new HashMap<Integer, HashMap<Integer, List<Integer>>>();        
            //Create a TreeMap to get a sorted list.
            TreeMap<CAInfo, Integer> sortedMap = new TreeMap<CAInfo, Integer>(new Comparator<CAInfo>() {
                @Override
                public int compare(CAInfo o1, CAInfo o2) {
                    return o1.getName().compareTo(o2.getName());
                }
            });
            // 1. Retrieve a list of all CA's the current user is authorized to
            for(CAInfo caInfo : casession.getAuthorizedAndNonExternalCaInfos(administrator)) {
                sortedMap.put(caInfo, caInfo.getCAId());
            }
            Collection<Integer> authorizedCas = sortedMap.values(); 
            //Cache certificate profiles to save on database transactions
            HashMap<Integer, CertificateProfile> certificateProfiles = new HashMap<Integer, CertificateProfile>();        
            // 2. Retrieve a list of all authorized end entity profile IDs
            for (Integer nextendentityprofileid : endEntityProfileSession.getAuthorizedEndEntityProfileIds(administrator)) {
                EndEntityProfile endentityprofile = endEntityProfileSession.getEndEntityProfile(nextendentityprofileid.intValue());
                // 3. Retrieve the list of CA's available to the current end entity profile
                String[] availableCAs = endentityprofile.getValue(EndEntityProfile.AVAILCAS, 0).split(EndEntityProfile.SPLITCHAR);
                List<Integer> casDefineInEndEntityProfile = new ArrayList<Integer>();
                for (String profileId : availableCAs) {
                    casDefineInEndEntityProfile.add(Integer.valueOf(profileId));
                }
                boolean allCasDefineInEndEntityProfile = false;
                if (casDefineInEndEntityProfile.contains(Integer.valueOf(SecConst.ALLCAS))) {
                    allCasDefineInEndEntityProfile = true;
                }
                // 4. Next retrieve all certificate profiles defined in the end entity profile
                String[] availableCertificateProfiles = endentityprofile.getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
                HashMap<Integer, List<Integer>> certificateProfileMap = new HashMap<Integer, List<Integer>>();
                for (String certificateProfileIdString : availableCertificateProfiles) {
                    Integer certificateProfileId = Integer.valueOf(certificateProfileIdString);
                    CertificateProfile certprofile = (CertificateProfile) certificateProfiles.get(certificateProfileId);
                    if (certprofile == null) {
                        certprofile = certificateProfileSession.getCertificateProfile(certificateProfileId.intValue());
                        //Cache the profile for repeated use
                        certificateProfiles.put(certificateProfileId, certprofile);
                    }
                    // 5. Retrieve all CAs defined in the current certificate profile
                    Collection<Integer> casDefinedInCertificateProfile = certprofile.getAvailableCAs();
                    // First make a clone of the full list of available CAs
                    List<Integer> authorizedCasClone = new ArrayList<Integer>(authorizedCas);
                    if (!casDefinedInCertificateProfile.contains(Integer.valueOf(CertificateProfile.ANYCA))) {
                        //If ANYCA wasn't defined among the list from the cert profile, only keep the intersection
                        authorizedCasClone.retainAll(casDefinedInCertificateProfile);
                    }
                    if (!allCasDefineInEndEntityProfile) {
                        //If ALL wasn't defined in the EE profile, only keep the intersection
                        authorizedCasClone.retainAll(casDefineInEndEntityProfile);
                    }             
                    certificateProfileMap.put(certificateProfileId, authorizedCasClone);
                }
                endentityavailablecas.put(nextendentityprofileid, certificateProfileMap);
            }
        }
        return endentityavailablecas.get(Integer.valueOf(endentityprofileid));
    }

    /**
     * Returns a administrators set of authorized available accessrules.
     * 
     * @return A HashSet containing the administrators authorized available accessrules.
     */

    public Map<String, Set<String>> getAuthorizedAccessRules() {
        if (authorizedaccessrules == null) {
            authorizedaccessrules = complexAccessControlSession.getAuthorizedAvailableAccessRules(administrator,
                    globalconfiguration.getEnableEndEntityProfileLimitations(), globalconfiguration.getIssueHardwareTokens(),
                    globalconfiguration.getEnableKeyRecovery(), endEntityProfileSession.getAuthorizedEndEntityProfileIds(administrator),
                    userdatasourcesession.getAuthorizedUserDataSourceIds(administrator, true), EjbcaConfiguration.getCustomAvailableAccessRules());
        }
        return authorizedaccessrules;
    }
    
    public Set<String> getAuthorizedAccessRulesUncategorized() {
        Set<String> accessRulesSet = new HashSet<String>();
        for(Entry<String, Set<String>> entry : getAuthorizedAccessRules().entrySet()) {
            accessRulesSet.addAll(entry.getValue());
        }
        return accessRulesSet;
    }

    /**
     * @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
     */
    public TreeMap<String, Integer> getHardTokenProfiles() {
        return hardtokenauthorization.getHardTokenProfiles();
    }

    /**
     * @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
     */
    public TreeMap<String, HardTokenIssuerInformation> getHardTokenIssuers() {
        return hardtokenauthorization.getHardTokenIssuers();
    }

    /**
     * @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
     */
    public Collection<RoleData> getHardTokenIssuingRoles() {
        return hardtokenauthorization.getHardTokenIssuingRoles();
    }

    /**
     * Returns a sorted map with authorized rolename -> roleid
     */

    public TreeMap<String, Integer> getAuthorizedRoles() {
        if (authRoles == null) {
            authRoles = new TreeMap<String, Integer>();

            for (RoleData role : roleManagementSession.getAllRolesAuthorizedToEdit(administrator)) {
                authRoles.put(role.getRoleName(), Integer.valueOf(role.getPrimaryKey()));
            }
        }
        return authRoles;
    }

    /**
     * Returns a map with authorized roleId -> roleName
     */

    public Map<Integer, String> getRoleIdToNameMap() {
        if (roldIdMap == null) {
            TreeMap<String, Integer> roleNames = getAuthorizedRoles();
            roldIdMap = new HashMap<Integer, String>();
            Iterator<String> iter = roleNames.keySet().iterator();
            while (iter.hasNext()) {
                String next = iter.next();
                roldIdMap.put(roleNames.get(next), next);
            }

        }

        return roldIdMap;
    }

    /**
     * Method that should be called every time CA configuration is edited.
     */
    public void cAsEdited() {
        authRoles = null;
        roldIdMap = null;
        caidtonamemap = null;
        endentityavailablecas = null;
        authorizedaccessrules = null;
        raauthorization.clear();
        caauthorization.clear();
        hardtokenauthorization.clear();
    }

    /**
     * Method that should be called every time a end entity profile has been edited
     */
    public void endEntityProfilesEdited() {
        endentityprofilenameproxy = null;
        endentityavailablecas = null;
        authorizedaccessrules = null;
        raauthorization.clear();
    }

    /**
     * Method that should be called every time a certificate profile has been edited
     */
    public void certificateProfilesEdited() {
        certificateprofilenameproxy = null;
        endentityavailablecas = null;
        raauthorization.clear();
        caauthorization.clear();
        hardtokenauthorization.clear();
    }

    /**
     * Method that should be called every time a publisher has been edited
     */
    public void publishersEdited() {
        publisheridtonamemap = null;
        publishernames = null;
    }

    /**
     * Method that should be called every time a administrative privilegdes has been edited
     */
    public void administrativePriviledgesEdited() {
        endentityavailablecas = null;
        authRoles = null;
        roldIdMap = null;
        raauthorization.clear();
        caauthorization.clear();
        hardtokenauthorization.clear();
    }

    /**
     * Method that should be called every time hard token issuers has been edited
     */
    public void hardTokenDataEdited() {
        hardtokenauthorization.clear();
    }

    /**
     * Method that should be called every time the system configuration has been edited
     */
    public void systemConfigurationEdited(GlobalConfiguration globalconfiguration) {
        this.globalconfiguration = globalconfiguration;
        raauthorization.clear();
        caauthorization.clear();
        hardtokenauthorization.clear();
        authorizedaccessrules = null;
    }
    
    public void cmpConfigurationEdited(CmpConfiguration cmpconfig) {
        this.cmpconfiguration = cmpconfig;
    }

    /**
     * Method that should be called every time the system configuration has been edited
     */
    public void userDataSourceEdited() {
        authorizedaccessrules = null;
    }
}
