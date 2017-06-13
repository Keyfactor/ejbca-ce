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
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
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

    private AuthenticationToken administrator;
    private CAAdminSessionLocal caAdminSession;
    private CaSessionLocal caSession;
    private EndEntityProfileSessionLocal endEntityProfileSession;
    private PublisherSessionLocal publisherSession;
    private CertificateProfileSessionLocal certificateProfileSession;
    private ApprovalProfileSessionLocal approvalProfileSession;

    // Memory variables.
    private RAAuthorization raauthorization = null;
    private CAAuthorization caauthorization = null;
    private HardTokenAuthorization hardtokenauthorization = null;

    private Map<Integer, String> caidtonamemap = null;
    private Map<Integer, HashMap<Integer, List<Integer>>> endentityavailablecas = null;
    private Map<Integer, String> publisheridtonamemap = null;

    private TreeMap<String, Integer> publishernames = null;

    private GlobalConfiguration globalConfiguration = null;
    private AvailableExtendedKeyUsagesConfiguration availableExtendedKeyUsagesConfiguration = null;
    private AvailableCustomCertificateExtensionsConfiguration availableCustomCertExtensionsConfiguration = null;
    private EndEntityProfileNameProxy endentityprofilenameproxy = null;
    private CertificateProfileNameProxy certificateprofilenameproxy = null;

    private EjbcaWebBean ejbcaWebBean;

    /** Creates a new instance of InformationMemory */
    public InformationMemory(AuthenticationToken authenticationToken, GlobalConfiguration globalconfiguration, AvailableExtendedKeyUsagesConfiguration ekuConfig, 
            AvailableCustomCertificateExtensionsConfiguration cceConfig, EjbcaWebBean ejbcaWebBean) {
        this.administrator = authenticationToken;
        this.globalConfiguration = globalconfiguration;
        this.availableExtendedKeyUsagesConfiguration = ekuConfig;
        this.availableCustomCertExtensionsConfiguration = cceConfig;
        this.ejbcaWebBean = ejbcaWebBean;
        this.caAdminSession = ejbcaWebBean.getEjb().getCaAdminSession();
        this.caSession = ejbcaWebBean.getEjb().getCaSession();
        this.endEntityProfileSession = ejbcaWebBean.getEjb().getEndEntityProfileSession();
        this.publisherSession = ejbcaWebBean.getEjb().getPublisherSession();
        this.certificateProfileSession = ejbcaWebBean.getEjb().getCertificateProfileSession();
        this.approvalProfileSession = ejbcaWebBean.getEjb().getApprovalProfileSession();
        final AuthorizationSessionLocal authorizationSession = ejbcaWebBean.getEjb().getAuthorizationSession();
        this.raauthorization = new RAAuthorization(authenticationToken, ejbcaWebBean.getEjb().getGlobalConfigurationSession(), authorizationSession, caSession, endEntityProfileSession);
        this.caauthorization = new CAAuthorization(authenticationToken, caSession, certificateProfileSession);
        this.hardtokenauthorization = new HardTokenAuthorization(authenticationToken, ejbcaWebBean.getEjb().getHardTokenSession(), authorizationSession);
    }

    public String getCertificateProfileName(int id) {
        return this.certificateProfileSession.getCertificateProfileName(id);
    }

    /**
     * Returns a Map of CA id (Integer) -> CA name (String).
     */
    public Map<Integer, String> getCAIdToNameMap() {
        if (caidtonamemap == null) {
            caidtonamemap = caSession.getCAIdToNameMap();
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
    public TreeMap<String, Integer> getAuthorizedEndEntityProfileNames(final String endentityAccessRule) {
        return this.raauthorization.getAuthorizedEndEntityProfileNames(endentityAccessRule);
    }
    
    /**
     * Returns a list of authorized end-entity profiles ids of profiles with missing CA Ids.
     */
    public List<Integer> getAuthorizedEndEntityProfileIdsWithMissingCAs() {
        return this.raauthorization.getViewAuthorizedEndEntityProfilesWithMissingCAs();
    }

    /**
     * Returns authorized end entity  profile names as a treemap of name (String) -> id (Integer)
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
        HashMap<Integer, String> idtonamemap = caSession.getCAIdToNameMap();
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
        Map<Integer, String> idtonamemap = this.caSession.getActiveCAIdToNameMap(administrator);
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
     * Returns authorized external CA names as a treemap of name (String) -> id (Integer).
     */
    public TreeMap<String, Integer> getExternalCAs() {
        TreeMap<String, Integer> externalcas = new TreeMap<String, Integer>();
        for (Integer caId : caauthorization.getAuthorizedCAIds()) {
            CAInfo caInfo;
            try {
                caInfo = caSession.getCAInfoInternal(caId);
            } catch (CADoesntExistsException e) {
                throw new IllegalStateException("Should not be able to happen, CA ID was just retrieved from the database.", e);
            }
            if (caInfo.getStatus() == CAConstants.CA_EXTERNAL) {
                externalcas.put(caInfo.getName(), caId);
            }          
        }
        return externalcas;
    }
    
    /**
     * Returns CA authorization string used in userdata queries.
     */
    public String getUserDataQueryCAAuthorizationString() {
        return this.raauthorization.getCAAuthorizationString();
    }

    /**
     * Returns CA authorization string used in userdata queries.
     */
    public String getUserDataQueryEndEntityProfileAuthorizationString(final String endentityAccessRule) {
        return this.raauthorization.getEndEntityProfileAuthorizationString(true, endentityAccessRule);
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
        return globalConfiguration;
    }
    
    public AvailableExtendedKeyUsagesConfiguration getAvailableExtendedKeyUsagesConfiguration() {
        return availableExtendedKeyUsagesConfiguration;
    }
    
    public AvailableCustomCertificateExtensionsConfiguration getAvailableCustomCertExtensionsConfiguration() {
        return availableCustomCertExtensionsConfiguration;
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
     * Method returning the all available approval profiles id to name.
     * 
     * @return the approvalprofiles-id-to-name-map (HashMap)
     */
    public Map<Integer, String> getApprovalProfileIdToNameMap() {
        Map<Integer, String> approvalProfileMap = approvalProfileSession.getApprovalProfileIdToNameMap();
        approvalProfileMap.put(-1, ejbcaWebBean.getText("NONE"));
        return approvalProfileMap;
    }
    
    public List<Integer> getSortedApprovalProfileIds() {    
        List<ApprovalProfile> sortedProfiles = new ArrayList<>(approvalProfileSession.getAllApprovalProfiles().values());
        Collections.sort(sortedProfiles, new Comparator<ApprovalProfile>() {
            @Override
            public int compare(ApprovalProfile o1, ApprovalProfile o2) {               
                return o1.getProfileName().compareToIgnoreCase(o2.getProfileName());
            }
        });
        List<Integer> result = new ArrayList<>();
        result.add(-1);
        for(ApprovalProfile approvalProfile : sortedProfiles) {
            result.add(approvalProfile.getProfileId());
        }
        return result;
    }
        
    /**
     * Method returning the all available publishers id to name.
     * 
     * @return the publisheridtonamemap (HashMap)
     */
    public Map<Integer, String> getPublisherIdToNameMap() {
        if (publisheridtonamemap == null) {
            publisheridtonamemap = publisherSession.getPublisherIdToNameMap();
        }
        return publisheridtonamemap;
    }
    
    /**
     * Method returning the all available publishers id to name.
     * 
     * @return the publisheridtonamemap (HashMap) sorted by value
     */
    public Map<Integer, String> getPublisherIdToNameMapByValue() {
        if (publisheridtonamemap == null) {
            publisheridtonamemap = publisherSession.getPublisherIdToNameMap();
        }
        List<Map.Entry<Integer, String>> publisherIdToNameMapList = new LinkedList<>(publisheridtonamemap.entrySet());
        Collections.sort(publisherIdToNameMapList, new Comparator<Map.Entry<Integer, String>>() {
            public int compare(Map.Entry<Integer, String> o1, Map.Entry<Integer, String> o2) {
                return (o1.getValue()).compareToIgnoreCase(o2.getValue());
            }
        });
        Map<Integer, String> sortedMap = new LinkedHashMap<>();
        for (Map.Entry<Integer, String> entry : publisherIdToNameMapList) {
            sortedMap.put(entry.getKey(), entry.getValue());
        }
        return sortedMap;
    }

    /**
     * Returns all authorized publishers names as a treemap of name (String) -> id (Integer).
     */
    public TreeMap<String, Integer> getAuthorizedPublisherNames() {
        if (publishernames == null) {
            publishernames = new TreeMap<String, Integer>(String.CASE_INSENSITIVE_ORDER);
            Map<Integer, String> idtonamemap = getPublisherIdToNameMap();
            for(Integer id : caAdminSession.getAuthorizedPublisherIds(administrator)) {
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

    public Map<Integer, List<Integer>> getCasAvailableToEndEntity(int endentityprofileid, final String endentityAccessRule) {
        if (endentityavailablecas == null) {
            endentityavailablecas = new HashMap<Integer, HashMap<Integer, List<Integer>>>();        
            //Create a TreeMap to get a sorted list.
            TreeMap<CAInfo, Integer> sortedMap = new TreeMap<CAInfo, Integer>(new Comparator<CAInfo>() {
                @Override
                public int compare(CAInfo o1, CAInfo o2) {
                    return o1.getName().compareToIgnoreCase(o2.getName());
                }
            });
            // 1. Retrieve a list of all CA's the current user is authorized to
            for(CAInfo caInfo : caSession.getAuthorizedAndNonExternalCaInfos(administrator)) {
                sortedMap.put(caInfo, caInfo.getCAId());
            }
            Collection<Integer> authorizedCas = sortedMap.values(); 
            //Cache certificate profiles to save on database transactions
            HashMap<Integer, CertificateProfile> certificateProfiles = new HashMap<Integer, CertificateProfile>();        
            // 2. Retrieve a list of all authorized end entity profile IDs
            for (Integer nextendentityprofileid : endEntityProfileSession.getAuthorizedEndEntityProfileIds(administrator, endentityAccessRule)) {
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
                    CertificateProfile certprofile = certificateProfiles.get(certificateProfileId);
                    if (certprofile == null) {
                        certprofile = certificateProfileSession.getCertificateProfile(certificateProfileId.intValue());
                        //Cache the profile for repeated use
                        certificateProfiles.put(certificateProfileId, certprofile);
                    }
                    // 5. Retrieve all CAs defined in the current certificate profile
                    final Collection<Integer> casDefinedInCertificateProfile;
                    if(certprofile != null) {
                        casDefinedInCertificateProfile = certprofile.getAvailableCAs();
                    } else {
                        casDefinedInCertificateProfile = new ArrayList<Integer>();
                    }
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
     * @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
     */
    public TreeMap<String, Integer> getHardTokenProfiles() {
        return hardtokenauthorization.getHardTokenProfiles();
    }

    public TreeMap<String, HardTokenIssuerInformation> getHardTokenIssuers() {
        return ejbcaWebBean.getEjb().getHardTokenSession().getHardTokenIssuers(administrator);
    }

    /**
     * Method that should be called every time CA configuration is edited.
     */
    public void cAsEdited() {
        caidtonamemap = null;
        endentityavailablecas = null;
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
     * Method that should be called every time hard token issuers has been edited
     */
    public void hardTokenDataEdited() {
        hardtokenauthorization.clear();
    }

    /**
     * Method that should be called every time the system configuration has been edited
     */
    public void systemConfigurationEdited(GlobalConfiguration globalconfiguration) {
        this.globalConfiguration = globalconfiguration;
        raauthorization.clear();
        caauthorization.clear();
        hardtokenauthorization.clear();
    }
    
    
    public void availableExtendedKeyUsagesConfigEdited(AvailableExtendedKeyUsagesConfiguration ekuConfig) {
        this.availableExtendedKeyUsagesConfiguration = ekuConfig;
    }
    
    public void availableCustomCertExtensionsConfigEdited(AvailableCustomCertificateExtensionsConfiguration cceConfig) {
        this.availableCustomCertExtensionsConfiguration = cceConfig;
    }
}
