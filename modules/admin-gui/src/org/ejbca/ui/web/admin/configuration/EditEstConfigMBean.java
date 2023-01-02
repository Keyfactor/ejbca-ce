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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Backing bean for edit EST alias view.
 *
 */
@Named
@ViewScoped
public class EditEstConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final String HIDDEN_PWD = "**********";

    private static final List<String> dnfields = Arrays.asList("CN", "UID", "OU", "O", "L", "ST", "DC", "C", "emailAddress", "SN", "givenName", "initials", "surname", "title", 
            "unstructuredAddress", "unstructuredName", "postalCode", "businessCategory", "dnQualifier", "postalAddress", 
            "telephoneNumber", "pseudonym", "streetAddress", "name", "role", "CIF", "NIF");

    private String selectedRaNameSchemeDnPart;

    @EJB
    private CaSessionLocal caSession;

    private TreeMap<Integer, String> caIdToNameMap;
    private TreeMap<String, Integer> caNameToIdMap;

    @Inject
    private EstConfigMBean estConfigMBean;
    EstAliasGui estAliasGui = null;

    @PostConstruct
    public void initialize() {
        getEjbcaWebBean().clearEstConfigClone();
        caIdToNameMap = (TreeMap<Integer, String>) caSession.getAuthorizedCaIdsToNames(getAdmin());
        caNameToIdMap = (TreeMap<String, Integer>) caSession.getAuthorizedCaNamesToIds(getAdmin());
    }

    public class EstAliasGui {
        private String name;
        private String caId;
        private String endEntityProfileId;
        private String certificateProfileId;
        private Boolean certificateRequired;
        private String userName;
        private String password;
        private Boolean allowSameKey;
        private String extUsernameComponent;
        private String operationmode;
        private String authModule;
        private String vendorCas;
        private String selectedVendorCa;
        private boolean vendorMode;
        private boolean allowChangeSubjectName;
        private String extDnPartPwdComponent;
        
        private boolean usesProxyCa;
        
        
        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getCaId() {
            return caId;
        }

        public void setCaId(String caId) {
            this.caId = caId;
        }

        public String getEndEntityProfileId() {
            return endEntityProfileId;
        }

        public void setEndEntityProfileId(String endEntityProfileId) {
            this.endEntityProfileId = endEntityProfileId;
        }

        public String getCertificateProfileId() {
            return certificateProfileId;
        }

        public void setCertificateProfileId(String certificateProfileId) {
            this.certificateProfileId = certificateProfileId;
        }

        public Boolean getCertificateRequired() {
            return certificateRequired;
        }

        public void setCertificateRequired(Boolean certificateRequired) {
            this.certificateRequired = certificateRequired;
        }

        public String getUserName() {
            return userName;
        }

        public void setUserName(String userName) {
            this.userName = userName;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public Boolean getAllowSameKey() {
            return allowSameKey;
        }

        public void setAllowSameKey(Boolean allowSameKey) {
            this.allowSameKey = allowSameKey;
        }
        
        public String getOperationMode() {
            return operationmode;
        }
        
        public void setOperationMode(String operationmode) {
            this.operationmode = operationmode;
        }
        
        public void setVendorMode(boolean vendorMode) {
            this.vendorMode = vendorMode;
        }
        
        public  boolean getVendorMode() {
            return this.vendorMode;
        }
        
        public void setAllowChangeSubjectName(boolean allowChangeSubjectName) {
            this.allowChangeSubjectName = allowChangeSubjectName;
        }
        
        public  boolean getAllowChangeSubjectName() {
            return this.allowChangeSubjectName;
        }
        
        public void setSelectedVendorCa(String selectedVendorCa) {
            this.selectedVendorCa = selectedVendorCa;
        }
        
        public  String getSelectedVendorCa() {
            return selectedVendorCa == null ? String.valueOf(getVendorCaSelectItems().get(0).getValue()) : selectedVendorCa;
        }
        
        public void setVendorCas(String vendorCas) {
            this.vendorCas = vendorCas;
        }
        
        
        public  String getVendorCas() {
            return vendorCas == null ? "" : vendorCas;
        }
        
        public void setAuthenticationModule(final String authModule) {
            this.authModule = authModule;
        }
        
        public String getAuthenticationModule() {
            return this.authModule;
        }
        
        public String getExtDnPartPwdComponent() {
            return extDnPartPwdComponent;
        }
        
        public void setExtDnPartPwdComponent(String extDnPartPwdComponent) {
            this.extDnPartPwdComponent = extDnPartPwdComponent;
        }
        
        public boolean getDnPartPwdSelected() {
            if (getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_DN_PART_PWD)) {
                return true;  
            }
            return false;
        }
        
        public void setDnPartPwdSelected(boolean dnPartPwdSelected) {
            if (dnPartPwdSelected) {
                setAuthenticationModule(EstConfiguration.CONFIG_AUTHMODULE_DN_PART_PWD);
            } else if (getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_DN_PART_PWD)) {
                setAuthenticationModule("");
            }
        }

        public void setHttpBasicAuthSelected(boolean selected) {
            if (selected) {
                setAuthenticationModule(EstConfiguration.CONFIG_AUTHMODULE_HTTP_BASIC_AUTH);
            } else {
                setAuthenticationModule("");
            }
        }

        public boolean getHttpBasicAuthSelected() {
            return getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_HTTP_BASIC_AUTH);
        }

        public boolean getChallengePwdSelected() {
            if (getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD)) {
                return true;  
            }
            return false;
        }
        
        public void setChallengePwdSelected(boolean challengePwdSelected) {
            if (challengePwdSelected) {
                setAuthenticationModule(EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD);
            } else if (getAuthenticationModule().equals(EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD)) {
                setAuthenticationModule("");
            }
        }
        
        public void setExtUsernameComponent(String extUsernameComponent) {
            this.extUsernameComponent = extUsernameComponent;
        }
        
        public String getExtUsernameComponent() {
            return extUsernameComponent;
        }

        public boolean isUsesProxyCa() {
            return usesProxyCa;
        }

        public void setUsesProxyCa(boolean usesProxyCa) {
            this.usesProxyCa = usesProxyCa;
        }
        
    }

    public EstAliasGui getEstAlias() throws NumberFormatException, AuthorizationDeniedException {
        if (estAliasGui == null) {
            EstAliasGui estAliasGui = new EstAliasGui();
            String aliasName = estConfigMBean.getSelectedAlias();
            estAliasGui.setName(aliasName);
            EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfiguration();
            estAliasGui.setCaId(estConfiguration.getDefaultCAID(aliasName));
            estAliasGui.setEndEntityProfileId(String.valueOf(estConfiguration.getEndEntityProfileID(aliasName)));
            String certProfileID = estConfiguration.getCertProfileID(aliasName);
            // If we had the old type, EJBCA 6.11 of CP, which is the name, convert it to ID
            if (certProfileID != null && !NumberUtils.isNumber(certProfileID)) {
                Map<String, Integer> certificateProfiles = getEjbcaWebBean().getCertificateProfilesNoKeyId(estAliasGui.getEndEntityProfileId());
                if (certificateProfiles.get(certProfileID) != null) {
                    certProfileID = String.valueOf(certificateProfiles.get(certProfileID));
                }
            }
            estAliasGui.setCertificateProfileId(certProfileID);
            estAliasGui.setCertificateRequired(estConfiguration.getCert(aliasName));
            estAliasGui.setUserName(estConfiguration.getUsername(aliasName));
            estAliasGui.setPassword(EditEstConfigMBean.HIDDEN_PWD);
            estAliasGui.setAllowSameKey(estConfiguration.getKurAllowSameKey(aliasName));
            estAliasGui.setExtUsernameComponent(estConfiguration.getExtractUsernameComponent(aliasName));
            estAliasGui.setOperationMode(estConfiguration.getOperationMode(aliasName));
            estAliasGui.setVendorMode(estConfiguration.getVendorMode(aliasName));
            estAliasGui.setAuthenticationModule(estConfiguration.getAuthenticationModule(aliasName));
            estAliasGui.setChallengePwdSelected(estConfiguration.getAuthenticationModule(aliasName).equals(EstConfiguration.CONFIG_AUTHMODULE_CHALLENGE_PWD));
            estAliasGui.setDnPartPwdSelected(estConfiguration.getAuthenticationModule(aliasName).equals(EstConfiguration.CONFIG_AUTHMODULE_DN_PART_PWD));
            estAliasGui.setExtDnPartPwdComponent(estConfiguration.getExtractDnPwdComponent(aliasName));
            estAliasGui.setAllowChangeSubjectName(estConfiguration.getAllowChangeSubjectName(aliasName));
            String vendorCaIds = estConfiguration.getVendorCaIds(aliasName);
            ArrayList<String> vendorCaNames = new ArrayList<>();
            if (!StringUtils.isEmpty(vendorCaIds)) {
                for (String vendorCaId : vendorCaIds.split(";")) {
                    String caName = caIdToNameMap.get(Integer.parseInt(vendorCaId));
                    vendorCaNames.add(caName);
                }
                estAliasGui.setVendorCas(StringUtils.join(vendorCaNames, ";"));
            } else {
                estAliasGui.setVendorCas("");
            }
            estAliasGui.setUsesProxyCa(estConfiguration.getSupportProxyCa(aliasName));
            this.estAliasGui = estAliasGui;
        }
        return estAliasGui;
    }


    public boolean isViewOnly() {
        return estConfigMBean.isViewOnly();
    }
    
    public boolean isRaMode() {
        return estAliasGui.getOperationMode().equals("ra");
    }
    
    public boolean isVendorMode() {
       return estAliasGui.getVendorMode();
    }
       
    public List<SelectItem> getExtUsernameComponentSelectItems() {
        final List<SelectItem> selectItems = getDnFieldSelectItems(); 
        selectItems.add(0, new SelectItem("DN"));
        return selectItems;
    }
    
    public List<SelectItem> getCaItemList() throws NumberFormatException, AuthorizationDeniedException {
        final List<SelectItem> ret = new ArrayList<>();
        if (StringUtils.isEmpty(getEstAlias().getCaId())) {
            ret.add(new SelectItem("", EjbcaJSFHelper.getBean().getText().get("ESTDEFAULTCA_DISABLED")));
        }
        for (String caname : caNameToIdMap.keySet()) {
            final Integer caId = caNameToIdMap.get(caname);
            ret.add(new SelectItem(caId, caname));
        }
        return ret;
    }

    public List<SelectItem> getEndEntityProfileItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        Map<String, String> nameToIdMap = getEjbcaWebBean().getAuthorizedEEProfilesAndIdsNoKeyId(AccessRulesConstants.CREATE_END_ENTITY);
        for (String endEntityProfileName : nameToIdMap.keySet()) {
            String endEntityProfileId = nameToIdMap.get(endEntityProfileName);
            ret.add(new SelectItem(endEntityProfileId, endEntityProfileName));
        }
        return ret;
    }

    public List<SelectItem> getCertificateProfileItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        if (estAliasGui.getEndEntityProfileId() != null) {
            Map<String, Integer> certificateProfiles = getEjbcaWebBean().getCertificateProfilesNoKeyId(estAliasGui.getEndEntityProfileId());
            for (String certificateProfileName : certificateProfiles.keySet()) {
                int certificateProfileId = certificateProfiles.get(certificateProfileName);
                ret.add(new SelectItem(certificateProfileId, certificateProfileName));
            }
        }
        return ret;
    }

    public String cancel() {
        reset();
        return "done";
    }

    public String save() throws AuthorizationDeniedException {
        String alias = estAliasGui.getName();
        EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        if (StringUtils.isEmpty(estAliasGui.getCaId())) {
            estConfiguration.setDefaultCAID(alias);
        } else {
            estConfiguration.setDefaultCAID(alias, Integer.valueOf(estAliasGui.getCaId()));
        }
        if (estAliasGui.getEndEntityProfileId() != null) {
            estConfiguration.setEndEntityProfileID(alias, Integer.valueOf(estAliasGui.getEndEntityProfileId()));
        }
        if (estAliasGui.getCertificateProfileId() != null) {
            estConfiguration.setCertProfileID(alias, Integer.valueOf(estAliasGui.getCertificateProfileId()));
        }
        estConfiguration.setCert(alias, estAliasGui.getCertificateRequired());
        estConfiguration.setUsername(alias, estAliasGui.getUserName());
        // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
        if (!estAliasGui.getPassword().equals(EditEstConfigMBean.HIDDEN_PWD)) {
            estConfiguration.setPassword(alias, estAliasGui.getPassword());
        }
        estConfiguration.setKurAllowSameKey(alias, estAliasGui.getAllowSameKey());
        estConfiguration.setExtractUsernameComponent(alias, estAliasGui.getExtUsernameComponent());
        estConfiguration.setExtractDnPwdComponent(alias, estAliasGui.getExtDnPartPwdComponent());
        estConfiguration.setOperationMode(alias, estAliasGui.getOperationMode());
        estConfiguration.setVendorMode(alias, estAliasGui.getVendorMode());
        estConfiguration.setAuthenticationModule(alias, estAliasGui.getAuthenticationModule());
        estConfiguration.setAllowChangeSubjectName(alias, estAliasGui.getAllowChangeSubjectName());
        final String currentVendorCas = getCurrentVendorCas();
        if (StringUtils.isEmpty(currentVendorCas)) {
            estConfiguration.setVendorCaIds(alias, "");
        } else {
            final String[] vendorCaNames = currentVendorCas.split(";");
            final ArrayList<String> vendorCaIds = new ArrayList<>();
            for (String vendorCaName : vendorCaNames) {
                Integer caId = caNameToIdMap.get(vendorCaName.trim());
                vendorCaIds.add(caId.toString());
            }
            estConfiguration.setVendorCaIds(alias, StringUtils.join(vendorCaIds, ";"));
        }
        updateSupportProxyCa();
        estConfiguration.setSupportProxyCa(alias, estAliasGui.isUsesProxyCa());
        getEjbcaWebBean().updateEstConfigFromClone(alias);
        reset();
        return "done";
    }
    
    
    public void actionAddVendorCa() {
        final String currentVendorCas = getCurrentVendorCas();
        List<String> currentVendorCaList = new ArrayList<>();
        if (StringUtils.isNotBlank(currentVendorCas)) {
            currentVendorCaList = new ArrayList<>(Arrays.asList(currentVendorCas.split(";"))); 
        }
        if (!currentVendorCaList.contains(estAliasGui.getSelectedVendorCa())) {
            currentVendorCaList.add(estAliasGui.getSelectedVendorCa());
        }
        setCurrentVendorCas(StringUtils.join(currentVendorCaList, ";"));
        updateSupportProxyCa();
    }
    
    public void actionRemoveVendorCa() {
        final String currentVendorCas = getCurrentVendorCas();
        if (StringUtils.isNotBlank(currentVendorCas)) {
            final List<String> currentVendorCaList = new ArrayList<>(Arrays.asList(currentVendorCas.split(";")));
            if (currentVendorCaList.remove(estAliasGui.getSelectedVendorCa())) {
                setCurrentVendorCas(StringUtils.join(currentVendorCaList, ";"));
                updateSupportProxyCa();
            }
        }
    }
    
    private void updateSupportProxyCa() {
        final AuthenticationToken authenticationToken = getAdmin();
        final CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
        estAliasGui.setUsesProxyCa(false); //default, repeated for remove action
        
        if (!isRaMode() && isVendorMode() && StringUtils.isNotBlank(getCurrentVendorCas())) {
            List<String> currentVendorCaList = new ArrayList<>(Arrays.asList(getCurrentVendorCas().split(";")));
            for (String caName : currentVendorCaList) {
                try {
                    if (caSession.getCAInfo(authenticationToken, caName).getCAType() == CAInfo.CATYPE_PROXY) {
                        estAliasGui.setUsesProxyCa(true);
                        return;
                    }
                } catch (AuthorizationDeniedException e) {
                    // should not happen
                    throw new IllegalStateException("Vendor CA is not authhorized.");
                }
            }
        }

        if (isRaMode() && StringUtils.isNotBlank(estAliasGui.getCaId())) {
            try {
                if (caSession.getCAInfo(authenticationToken, Integer.valueOf(estAliasGui.getCaId())).getCAType() == CAInfo.CATYPE_PROXY) {
                    estAliasGui.setUsesProxyCa(true);
                }
            } catch (AuthorizationDeniedException e) {
                // should not happen
                throw new IllegalStateException("RA CA is not authhorized.");
            }
        }
    }
    
    public List<SelectItem> getVendorCaSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        for (Integer caId : caIdToNameMap.keySet()) {
            selectItems.add(new SelectItem(caIdToNameMap.get(caId)));
        }
        return selectItems;
    }
    
    private String vendorCas;
    
    public String getCurrentVendorCas() {
        return vendorCas == null? estAliasGui.getVendorCas(): vendorCas;
    }
    
    public void setCurrentVendorCas(String vendorCas) {
        this.vendorCas = vendorCas;
    }
           
    /**
     * Add DN field to name generation parameter
     *
     */
    public void actionAddRaNameSchemeDnPart() {
    	String alias = estAliasGui.getName();
    	EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        String currentNameGenParam = estConfiguration.getRANameGenParams(getSelectedEstAlias());
        String[] params = currentNameGenParam == null ? new String[0] : currentNameGenParam.split(";");
        // Verify that current param is instance of DN fields
        if((params.length > 0) && ( dnfields.contains(params[0]) )) {
            if(!ArrayUtils.contains(params, getSelectedRaNameSchemeDnPart())) {
                currentNameGenParam += ";" + getSelectedRaNameSchemeDnPart();
            }
        } else {
                currentNameGenParam = getSelectedRaNameSchemeDnPart();
        }
        estConfiguration.setRANameGenParams(getSelectedEstAlias(), currentNameGenParam);
    }

    /**
     * Remove DN field from name generation parameter
     *
     */    
    public void actionRemoveRaNameSchemeDnPart() {
    	String alias = estAliasGui.getName();
    	EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        String currentNameGenParam = estConfiguration.getRANameGenParams(getSelectedEstAlias());
        if(StringUtils.contains(currentNameGenParam, getSelectedRaNameSchemeDnPart())) {
            String[] params = currentNameGenParam.split(";");
            if(params.length == 1) {
                currentNameGenParam = "";
            } else {
                if(StringUtils.equals(params[0], getSelectedRaNameSchemeDnPart())) {
                    currentNameGenParam = StringUtils.remove(currentNameGenParam, getSelectedRaNameSchemeDnPart() + ";");
                } else {
                    currentNameGenParam = StringUtils.remove(currentNameGenParam, ";" + getSelectedRaNameSchemeDnPart());
                }
            }
            estConfiguration.setRANameGenParams(getSelectedEstAlias(), currentNameGenParam);
        }
    }

    /**
     * Set the name generation scheme: DN/RANDOM/FIXED/USERNAME
     *
     */ 
    public void setRaNameGenScheme(final String scheme) {
    	String alias = estAliasGui.getName();
    	EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        estConfiguration.setRANameGenScheme(getSelectedEstAlias(), scheme);
    }
    
    /**
     * Get the name generation scheme: DN/RANDOM/FIXED/USERNAME
     *
     */     
    public String getRaNameGenScheme() {
    	String alias = estAliasGui.getName();
    	EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        return estConfiguration.getRANameGenScheme(getSelectedEstAlias());
    }    

    public String getSelectedEstAlias() {
        return estConfigMBean.getSelectedAlias();
    }

    /**
     * Get the available RA name generation schemes for radio buttons
     *
     */ 
    public List<SelectItem> getAvailableRaNameGenSchemes() {
        List<SelectItem> selectItems = new ArrayList<>();
        selectItems.add(new SelectItem(UsernameGeneratorParams.DN));
        selectItems.add(new SelectItem(UsernameGeneratorParams.RANDOM));
        selectItems.add(new SelectItem(UsernameGeneratorParams.FIXED));
        selectItems.add(new SelectItem(UsernameGeneratorParams.USERNAME));
        return selectItems;
    }

    /**
     * Set the name generation parameters
     * Semicolon delimited DN Fields
     *
     */ 
    public void setRaNameGenParams(final String params) {
    	String alias = estAliasGui.getName();
    	EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        estConfiguration.setRANameGenParams(getSelectedEstAlias(), params);
    }

    /**
     * Get the name generation parameters
     * Semicolon delimited DN Fields
     *
     */     
    public String getRaNameGenParams() {
    	String alias = estAliasGui.getName();
    	EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        return estConfiguration.getRANameGenParams(getSelectedEstAlias());
    }

    /**
     * Get the selected name generation DN part for addition or removal
     *
     */ 
    public String getSelectedRaNameSchemeDnPart() {
        return selectedRaNameSchemeDnPart == null ? dnfields.get(0) : selectedRaNameSchemeDnPart;
    }

    /**
     * Set the selected name generation DN part for addition or removal
     *
     */ 
    public void setSelectedRaNameSchemeDnPart(final String selectedRaNameSchemeDnPart) {
        this.selectedRaNameSchemeDnPart = selectedRaNameSchemeDnPart;
    }

    /**
     * Get the DN field select items. Full list of available DN fields.
     *
     */ 
    public List<SelectItem> getDnFieldSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        for (String  dnField : dnfields) {
            selectItems.add(new SelectItem(dnField));
        }
        return selectItems;
    }

    /**
     * Set the RA name generation prefix
     *
     */ 
    public void setRaNameGenPrefix(final String prefix) {
        String alias = estAliasGui.getName();
        EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        estConfiguration.setRANameGenPrefix(getSelectedEstAlias(), prefix);
    }

    /**
     * Get the RA name generation prefix
     *
     */     
    public String getRaNameGenPrefix() {
        String alias = estAliasGui.getName();
        EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        return estConfiguration.getRANameGenPrefix(getSelectedEstAlias());
    }

    /**
     * Set the RA name generation postfix
     *
     */ 
    public void setRaNameGenPostfix(final String prefix) {
        String alias = estAliasGui.getName();
        EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        estConfiguration.setRANameGenPostfix(getSelectedEstAlias(), prefix);
    }

    /**
     * Get the RA name generation postfix
     *
     */     
    public String getRaNameGenPostfix() {
        String alias = estAliasGui.getName();
        EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        return estConfiguration.getRANameGenPostfix(getSelectedEstAlias());
    }

    private void reset() {
        estAliasGui = null;
        getEjbcaWebBean().clearEstConfigClone();
        estConfigMBean.actionCancel();
    }

    public EstConfigMBean getEstConfigMBean() {
        return estConfigMBean;
    }

    public void setEstConfigMBean(EstConfigMBean estConfigMBean) {
        this.estConfigMBean = estConfigMBean;
    }
}