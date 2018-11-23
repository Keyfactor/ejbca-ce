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

package org.ejbca.ui.web.admin.cmp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * 
 * @version $Id$
 *
 */
//@ManagedBean
//@ViewScoped
public class EditCmpConfigMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EditCmpConfigMBean.class);

    // TODO available elsewhere perhaps?
    private static final List<String> dnfields = Arrays.asList("CN", "UID", "OU", "O", "L", "ST", "DC", "C", "emailAddress", "SN", "givenName", "initials", "surname", "title", 
            "unstructuredAddress", "unstructuredName", "postalCode", "businessCategory", "dnQualifier", "postalAddress", 
            "telephoneNumber", "pseudonym", "streetAddress", "name", "CIF", "NIF");
    @EJB
    private GlobalConfigurationSessionLocal globalConfigSession;
    
    @PostConstruct
    public void initialize() {
        getEjbcaWebBean().clearCmpConfigClone();
        cmpConfiguration = getEjbcaWebBean().getCmpConfigForEdit(getSelectedCmpAlias());
        initAuthModule();
    }
    
    private CmpConfiguration cmpConfiguration;
    private CmpConfigMBean cmpConfigBean;
    private String selectedRaNameSchemeDnPart;
    private String selectedCmpResponseAdditionalCaCert;
    
    // Authentication module specific
    private boolean hmacSelected;
    private boolean hmacSharedSecret;
    private String hmacParam;
    
    private boolean eeCertSelected;
    private String selectedIssuerCa;
    
    private boolean regTokenPwdSelected;
    
    private boolean dnPartPwdSelected;
    private String selectedDnField;
    
    public String cancel() {
        return "done";
    }
    
    public String save() throws AuthorizationDeniedException {
        if (getRaNameGenScheme().equals(UsernameGeneratorParams.RANDOM) ||
                getRaNameGenScheme().equals(UsernameGeneratorParams.USERNAME)) {
            setRaNameGenParams("");
        }
        if (hmacSelected && hmacSharedSecret) {
            setAuthParameter(CmpConfiguration.AUTHMODULE_HMAC, "-");
        } else if (!hmacSelected) {
            setAuthParameter(CmpConfiguration.AUTHMODULE_HMAC ,"");
        } else {
            setAuthParameter(CmpConfiguration.AUTHMODULE_HMAC, hmacParam);
        }
        // TODO prevent save with no auth module selected
        
        if (!eeCertSelected) {
            setAuthParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, "");
        } else if (!isRaMode() && eeCertSelected) {
            setAuthParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, "-");
        } else {
            setAuthParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, selectedIssuerCa);
        }
        
        setAuthParameter(CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD, regTokenPwdSelected ? "-" : "");
        
        if (!dnPartPwdSelected || isRaMode()) {
            setAuthParameter(CmpConfiguration.AUTHMODULE_DN_PART_PWD, "");
        } else {
            setAuthParameter(CmpConfiguration.AUTHMODULE_DN_PART_PWD, selectedDnField);
        }
        
        getEjbcaWebBean().updateCmpConfigFromClone(getSelectedCmpAlias());
        return "done";
    }
    
    public void actionAddRaNameSchemeDnPart() {
        String currentNameGenParam = cmpConfiguration.getRANameGenParams(getSelectedCmpAlias());
        String[] params = currentNameGenParam == null ? new String[0] : currentNameGenParam.split(";");
        // First item of list is initially rendered as selected, though not set in practice.
        selectedRaNameSchemeDnPart = selectedRaNameSchemeDnPart == null ? dnfields.get(0) : selectedRaNameSchemeDnPart;
        // Verify that current param is instance of DN fields
        if((params.length > 0) && ( dnfields.contains(params[0]) )) {
            if(!ArrayUtils.contains(params, selectedRaNameSchemeDnPart)) {
                currentNameGenParam += ";" + selectedRaNameSchemeDnPart;
            } else {
                // TODO Error message "DN part already added"
            }
        } else {
                currentNameGenParam = selectedRaNameSchemeDnPart;
        }
        cmpConfiguration.setRANameGenParams(getSelectedCmpAlias(), currentNameGenParam);
    }
    
    public void actionRemoveRaNameSchemeDnPart() {
        String currentNameGenParam = cmpConfiguration.getRANameGenParams(getSelectedCmpAlias());
        selectedRaNameSchemeDnPart = selectedRaNameSchemeDnPart == null ? dnfields.get(0) : selectedRaNameSchemeDnPart;
        if(StringUtils.contains(currentNameGenParam, selectedRaNameSchemeDnPart)) {
            String[] params = currentNameGenParam.split(";");
            if(params.length == 1) {
                currentNameGenParam = "";
            } else {
                if(StringUtils.equals(params[0], selectedRaNameSchemeDnPart)) {
                    currentNameGenParam = StringUtils.remove(currentNameGenParam, selectedRaNameSchemeDnPart + ";");
                } else {
                    currentNameGenParam = StringUtils.remove(currentNameGenParam, ";" + selectedRaNameSchemeDnPart);
                }
            }
            cmpConfiguration.setRANameGenParams(getSelectedCmpAlias(), currentNameGenParam);
        }
    }
    
    public List<SelectItem> getCaNameSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        Map<String, Integer> caNameMap = getEjbcaWebBean().getCANames();
        for (String ca : caNameMap.keySet()) {
            selectItems.add(new SelectItem(ca));
        }
        return selectItems;
    }
    
    public List<SelectItem> getDnFieldSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        for (String  dnField : dnfields) {
            selectItems.add(new SelectItem(dnField));
        }
        return selectItems;
    }
    
    public List<SelectItem> getVendorCaSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        final TreeMap<String, Integer> caOptions = getEjbcaWebBean().getCAOptions();
        for (String ca : caOptions.keySet()) {
            selectItems.add(new SelectItem(ca));
        }
        return selectItems;
    }
    
    public List<SelectItem> getRaEeProfileSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        final Map<String, String> availableEeps = getEjbcaWebBean().getAuthorizedEEProfileNamesAndIds(AccessRulesConstants.CREATE_END_ENTITY);
        for (Map.Entry<String, String> entry : availableEeps.entrySet()) {
            selectItems.add(new SelectItem(entry.getValue(), entry.getKey()));
        }
        return selectItems;
    }
    
    public List<SelectItem> getRaCertProfileSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        final Collection<String> availableCps = getEjbcaWebBean().getAvailableCertProfilesOfEEProfile(getRaEeProfile());
        selectItems.add(new SelectItem(CmpConfiguration.PROFILE_DEFAULT));
        for (String certProfile : availableCps) {
            selectItems.add(new SelectItem(certProfile));
        }
        return selectItems;
    }
    
    // TODO error handling
    public List<SelectItem> getRaCaSelectItems() throws NumberFormatException, CADoesntExistsException, AuthorizationDeniedException {
        final List<SelectItem> selectItems = new ArrayList<>();
        final Collection<String> availableCas = getEjbcaWebBean().getAvailableCAsOfEEProfile(getRaEeProfile());
        selectItems.add(new SelectItem(CmpConfiguration.PROFILE_DEFAULT));
        for (String ca : availableCas) {
            selectItems.add(new SelectItem(ca));
        }
        return selectItems;
    }
    
    public List<SelectItem> getCmpResponseProtectionSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        final Collection<String> availableResponseProtections = cmpConfiguration.getCmpResponseProtectionList(isRaMode());
        for (String responseProtection : availableResponseProtections) {
            selectItems.add(new SelectItem(responseProtection));
        }
        return selectItems;
    }
    
    public List<SelectItem> getCmpResponseAdditionalCaCerts() {
        final List<SelectItem> selectItems = new ArrayList<>();
        final TreeMap<String, Integer> caIdMap = getEjbcaWebBean().getCAOptions();
        for (Map.Entry<String, Integer> entry : caIdMap.entrySet()) {
            selectItems.add(new SelectItem(entry.getValue(), entry.getKey()));
        }
        return selectItems;
    }
    
    public CmpConfigMBean getCmpConfigMBean() {
        return cmpConfigBean;
    }

    public void setCmpConfigMBean(CmpConfigMBean cmpConfigBean) {
        this.cmpConfigBean = cmpConfigBean;
    }
    
    public String getSelectedCmpAlias() {
        return cmpConfigBean.getSelectedCmpAlias();
    }

    public boolean isRaMode() {
        return getOperationalMode().equals("ra");
    }
    
    /**           CMP Authentication Modules              **/
    
    private void setAuthParameter(String module, String parameter) {
        ArrayList<String> authModules = new ArrayList<>();
        ArrayList<String> authParams = new ArrayList<>();
        authModules.add(module);
        authParams.add(parameter);
        cmpConfiguration.setAuthenticationProperties(getSelectedCmpAlias(), authModules, authParams);
    }
    
    private void initAuthModule() {
        final String hmacAuthParam = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_HMAC, getSelectedCmpAlias());
        final String eeCertParam = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, getSelectedCmpAlias());
        final String regTokenPwdParam = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD, getSelectedCmpAlias());
        final String dnPartPwdParam = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_DN_PART_PWD, getSelectedCmpAlias());
        hmacSelected = !StringUtils.isEmpty(hmacAuthParam);
        hmacParam = hmacAuthParam;
        if (hmacAuthParam.isEmpty() || hmacAuthParam.equals("-")) {
            hmacSharedSecret = true;
            hmacParam = "";
        }
        eeCertSelected = !StringUtils.isEmpty(eeCertParam);
        selectedIssuerCa = eeCertParam;
        regTokenPwdSelected = regTokenPwdParam.equals("-");
        dnPartPwdSelected = !StringUtils.isEmpty(dnPartPwdParam);
        selectedDnField = dnPartPwdParam;
    }
    
    public void setHmacSelected(final boolean hmacSelected) {
       this.hmacSelected = hmacSelected;
    }
    
    public boolean isHmacSelected() {
        return hmacSelected;
    }
    
    public void setHmacSecret(String hmacSecret) {
        this.hmacParam = hmacSecret;
    }
    
    public String getHmacSecret() {
        return hmacParam;
    }

    public void setHmacSecretMode(String mode) {
        if (mode.equals("shared")) {
            hmacSharedSecret = true;
        } else {
            hmacSharedSecret = false;
        }
    }
    
    public String getHmacSecretMode() {
        if (hmacSharedSecret) {
            return "shared";
        }
        return "specified";
    }
    
    public boolean isHmacSecretShared() {
        return hmacSharedSecret;
    }
    
    public boolean isEeCertSelected() {
        return eeCertSelected;
    }

    public void setEeCertSelected(boolean eeCertSelected) {
        this.eeCertSelected = eeCertSelected;
    }

    public String getSelectedIssuerCa() {
        return selectedIssuerCa;
    }

    public void setSelectedIssuerCa(String selectedIssuerCa) {
        this.selectedIssuerCa = selectedIssuerCa;
    }

    public void setRegTokenPwdSelected(final boolean regTokenPwdSelected) {
        this.regTokenPwdSelected = regTokenPwdSelected;
    }
    
    public boolean isRegTokenPwdSelected() {
        return regTokenPwdSelected;
    }
    
    public void setDnPartPwdSelected(final boolean dnPartPwdSelected) {
        this.dnPartPwdSelected = dnPartPwdSelected;
    }
    
    public boolean isDnPartPwdSelected() {
        return dnPartPwdSelected;
    }
    
    public String getSelectedDnField() {
        return selectedDnField;
    }

    public void setSelectedDnField(String selectedDnField) {
        this.selectedDnField = selectedDnField;
    }

    
    // Not convenient way of toggling boolean, though required due to limitations with <h:selectOneRadio>
    public void setOperationalMode(String mode) {
        if (mode.equals("ra")) {
            cmpConfiguration.setRAMode(getSelectedCmpAlias(), true);
        } else {
            cmpConfiguration.setRAMode(getSelectedCmpAlias(), false);
        }
    }
    
    public String getOperationalMode() {
        if (cmpConfiguration.getRAMode(getSelectedCmpAlias())) {
            return "ra";
        }
        return "client";
    }
    
    
    public boolean isCaSharedSecret() {
        return getHmacSecretMode().equals("shared");
    }

    
    /**           Client mode                                            **/
    
    public void setSelectedUsernameComponent(String component) {
        cmpConfiguration.setExtractUsernameComponent(getSelectedCmpAlias(), component);
    }
    
    public String getSelectedUsernameComponent() {
        return cmpConfiguration.getExtractUsernameComponent(getSelectedCmpAlias());
    }
    
    public void setRaNameGenPrefix(String prefix) {
        cmpConfiguration.setRANameGenPrefix(getSelectedCmpAlias(), prefix);
    }
    
    public String getRaNameGenPrefix() {
        return cmpConfiguration.getRANameGenPrefix(getSelectedCmpAlias());
    }

    public void setRaNameGenPostfix(String prefix) {
        cmpConfiguration.setRANameGenPostfix(getSelectedCmpAlias(), prefix);
    }
    
    public String getRaNameGenPostfix() {
        return cmpConfiguration.getRANameGenPostfix(getSelectedCmpAlias());
    }
    
    public void setVendorMode(final boolean mode) {
        cmpConfiguration.setVendorMode(getSelectedCmpAlias(), mode);
    }
    
    public boolean getVendorMode() {
        return cmpConfiguration.getVendorMode(getSelectedCmpAlias());
    }
    
    public void setVendorCa(String ca) {
        cmpConfiguration.setVendorCA(getSelectedCmpAlias(), ca);
    }
    
    public String getVendorCa() {
        return cmpConfiguration.getVendorCA(getSelectedCmpAlias());
    }
    
    /**           RA mode                                               **/
    
    public void setAllowRaVerifyPopo(final boolean allow) {
        cmpConfiguration.setAllowRAVerifyPOPO(getSelectedCmpAlias(), allow);
    }
    
    public boolean getAllowRaVerifyPopo() {
        return cmpConfiguration.getAllowRAVerifyPOPO(getSelectedCmpAlias());
    }

    public void setRaNameGenScheme(String scheme) {
        cmpConfiguration.setRANameGenScheme(getSelectedCmpAlias(), scheme);
    }
    
    public String getRaNameGenScheme() {
        return cmpConfiguration.getRANameGenScheme(getSelectedCmpAlias());
    }
    
    public List<SelectItem> getAvailableRaNameGenSchemes() {
        List<SelectItem> selectItems = new ArrayList<>();
        selectItems.add(new SelectItem(UsernameGeneratorParams.DN));
        selectItems.add(new SelectItem(UsernameGeneratorParams.RANDOM));
        selectItems.add(new SelectItem(UsernameGeneratorParams.FIXED));
        selectItems.add(new SelectItem(UsernameGeneratorParams.USERNAME));
        return selectItems;
    }
    
    public void setRaNameGenParams(String params) {
        cmpConfiguration.setRANameGenParams(getSelectedCmpAlias(), params);
    }
    
    public String getRaNameGenParams() {
        return cmpConfiguration.getRANameGenParams(getSelectedCmpAlias());
    }

    public String getSelectedRaNameSchemeDnPart() {
        return selectedRaNameSchemeDnPart;
    }

    public void setSelectedRaNameSchemeDnPart(String selectedRaNameSchemeDnPart) {
        this.selectedRaNameSchemeDnPart = selectedRaNameSchemeDnPart;
    }
    
    public void setRaPwdGenParams(String password) {
        cmpConfiguration.setRAPwdGenParams(getSelectedCmpAlias(), password);
    }
    
    public String getRaPwdGenParams() {
        return cmpConfiguration.getRAPwdGenParams(getSelectedCmpAlias());
    }
    
    public void setAllowRaCustomSerno(final boolean allow) {
        cmpConfiguration.setAllowRACustomSerno(getSelectedCmpAlias(), allow);
    }
    
    public boolean getAllowRaCustomSerno() {
        return cmpConfiguration.getAllowRACustomSerno(getSelectedCmpAlias());
    }
    
    public void setRaEeProfile(String profile) {
        cmpConfiguration.setRAEEProfile(getSelectedCmpAlias(), profile);
    }
    
    public String getRaEeProfile() {
        return cmpConfiguration.getRAEEProfile(getSelectedCmpAlias());
    }
    
    public void setRaCertProfile(String profile) {
        cmpConfiguration.setRACertProfile(getSelectedCmpAlias(), profile);
    }
    
    public String getRaCertProfile() {
        return cmpConfiguration.getRACertProfile(getSelectedCmpAlias());
    }
    
    public void setRaCaName(String caName) {
        cmpConfiguration.setRACAName(getSelectedCmpAlias(), caName);
    }
    
    public String getRaCaName() {
        return cmpConfiguration.getRACAName(getSelectedCmpAlias());
    }
    
    /**           Response Configuration                           **/
    
    public void setResponseProtection(String mode) {
        if (mode.equals("pbe")) {
            hmacSelected = true;
            eeCertSelected = false;
            selectedIssuerCa = "";
        }
        cmpConfiguration.setResponseProtection(getSelectedCmpAlias(), mode);
    }
    
    public String getResponseProtection() {
        return cmpConfiguration.getResponseProtection(getSelectedCmpAlias());
    }

    public void setSelectedCmpResponseAdditionalCaCert(String selectedCmpResponseAdditionalCaCert) {
        this.selectedCmpResponseAdditionalCaCert = selectedCmpResponseAdditionalCaCert;
    }
    
    public String getSelectedCmpResponseAdditionalCaCert() {
        return selectedCmpResponseAdditionalCaCert;
    }
    
    //TODO Error handling
    public String getSelectedCmpResponseAdditionalCaCertList() throws NumberFormatException, AuthorizationDeniedException {
        final String responseCaPubsCaList = cmpConfiguration.getResponseCaPubsCA(getSelectedCmpAlias());
        return getEjbcaWebBean().getCaNamesString(responseCaPubsCaList);
    }
    
    public void actionAddResponseAdditionalCaCert() {
        final String responseCaPubsCaList = cmpConfiguration.getResponseCaPubsCA(getSelectedCmpAlias());
        List<String> newResponseCaPubsCaList = new ArrayList<String>();
        selectedCmpResponseAdditionalCaCert = selectedCmpResponseAdditionalCaCert == null ? 
                String.valueOf(getCmpResponseAdditionalCaCerts().get(0).getValue()) : selectedCmpResponseAdditionalCaCert;
        if (StringUtils.isNotBlank(responseCaPubsCaList)) {
            newResponseCaPubsCaList = (List<String>) new ArrayList<String>(Arrays.asList( responseCaPubsCaList.split(";")));
        }
        if (!newResponseCaPubsCaList.contains(selectedCmpResponseAdditionalCaCert)) {
            newResponseCaPubsCaList.add(selectedCmpResponseAdditionalCaCert);
        }
        cmpConfiguration.setResponseCaPubsCA(getSelectedCmpAlias(), StringUtils.join(newResponseCaPubsCaList, ";"));
    }
    
    public void removeAddResponseAdditionalCaCert() {
        final String responseCaPubsCaList = cmpConfiguration.getResponseCaPubsCA(getSelectedCmpAlias());
        selectedCmpResponseAdditionalCaCert = selectedCmpResponseAdditionalCaCert == null ? 
                String.valueOf(getCmpResponseAdditionalCaCerts().get(0).getValue()) : selectedCmpResponseAdditionalCaCert;
        if (StringUtils.isNotBlank(responseCaPubsCaList)) {
            final List<String> list = new ArrayList<String>((List<String>) Arrays.asList(responseCaPubsCaList.split(";")));
            if (list.remove(selectedCmpResponseAdditionalCaCert)) {
                cmpConfiguration.setResponseCaPubsCA(getSelectedCmpAlias(), StringUtils.join(list, ";"));
            }
        }
    }
    
}

















