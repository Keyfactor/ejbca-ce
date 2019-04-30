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
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JavaServer Faces Managed Bean for editing CMP alias.
 * @version $Id$
 *
 */
@ManagedBean
@ViewScoped
public class EditCmpConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final List<String> dnfields = Arrays.asList("CN", "UID", "OU", "O", "L", "ST", "DC", "C", "emailAddress", "SN", "givenName", "initials", "surname", "title", 
            "unstructuredAddress", "unstructuredName", "postalCode", "businessCategory", "dnQualifier", "postalAddress", 
            "telephoneNumber", "pseudonym", "streetAddress", "name", "CIF", "NIF");
    
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigSession;
    
    @ManagedProperty(value="#{cmpConfigMBean}")
    private CmpConfigMBean cmpConfigMBean;

    @PostConstruct
    public void initialize() {
        getEjbcaWebBean().clearCmpConfigClone();
        cmpConfiguration = getEjbcaWebBean().getCmpConfigForEdit(getSelectedCmpAlias());
        initAuthModule();
    }
    
    public void authorize() throws Exception {
        // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
        }
    }
    
    private CmpConfiguration cmpConfiguration;
    
    private String selectedRaNameSchemeDnPart;
    private String selectedVendorCa;
    private String selectedCmpResponseAdditionalCaCert;
    private String selectedPkiResponseAdditionalCaCert;
    
    // Authentication module specific
    private boolean hmacSelected;
    private boolean hmacSharedSecret;
    private boolean eeCertSelected;
    private boolean regTokenPwdSelected;
    private boolean dnPartPwdSelected;
    private String hmacParam;
    private String selectedIssuerCa;
    private String selectedDnField;
    
    public String cancel() {
        return "done";
    }
    
    public String save() throws AuthorizationDeniedException {
        if (getRaNameGenScheme().equals(UsernameGeneratorParams.RANDOM) ||
                getRaNameGenScheme().equals(UsernameGeneratorParams.USERNAME)) {
            setRaNameGenParams("");
        }
        
        setAuthParameters();
        
        getEjbcaWebBean().updateCmpConfigFromClone(getSelectedCmpAlias());
        return "done";
    }
    
    public void actionAddRaNameSchemeDnPart() {
        String currentNameGenParam = cmpConfiguration.getRANameGenParams(getSelectedCmpAlias());
        String[] params = currentNameGenParam == null ? new String[0] : currentNameGenParam.split(";");
        // Verify that current param is instance of DN fields
        if((params.length > 0) && ( dnfields.contains(params[0]) )) {
            if(!ArrayUtils.contains(params, getSelectedRaNameSchemeDnPart())) {
                currentNameGenParam += ";" + getSelectedRaNameSchemeDnPart();
            }
        } else {
                currentNameGenParam = getSelectedRaNameSchemeDnPart();
        }
        cmpConfiguration.setRANameGenParams(getSelectedCmpAlias(), currentNameGenParam);
    }
    
    public void actionRemoveRaNameSchemeDnPart() {
        String currentNameGenParam = cmpConfiguration.getRANameGenParams(getSelectedCmpAlias());
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
            cmpConfiguration.setRANameGenParams(getSelectedCmpAlias(), currentNameGenParam);
        }
    }
    
    /** Select item lists for rendering **/
    
    public List<SelectItem> getCaNameSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        Map<String, Integer> caNameMap = getEjbcaWebBean().getCANames();
        for (String ca : caNameMap.keySet()) {
            selectItems.add(new SelectItem(ca));
        }
        return selectItems;
    }
    
    public List<SelectItem> getCertConfirmCaSelectItems() {
        List<SelectItem> caOptions = getCaNameSelectItems();
        caOptions.add(0, new SelectItem(getEjbcaWebBean().getText("CMPDEFAULTCA_DISABLED")));
        return caOptions;
    }
    
    public List<SelectItem> getDnFieldSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        for (String  dnField : dnfields) {
            selectItems.add(new SelectItem(dnField));
        }
        return selectItems;
    }
    
    public List<SelectItem> getExtUsernameComponentSelectItems() {
        final List<SelectItem> selectItems = getDnFieldSelectItems();
        selectItems.add(0, new SelectItem("DN"));
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
    
    public List<SelectItem> getAdditionalCaCertSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        final TreeMap<String, Integer> caIdMap = getEjbcaWebBean().getCAOptions();
        for (Map.Entry<String, Integer> entry : caIdMap.entrySet()) {
            selectItems.add(new SelectItem(entry.getValue(), entry.getKey()));
        }
        return selectItems;
    }
    
    public CmpConfigMBean getCmpConfigMBean() {
        return cmpConfigMBean;
    }

    public void setCmpConfigMBean(CmpConfigMBean cmpConfigBean) {
        this.cmpConfigMBean = cmpConfigBean;
    }
    
    public String getSelectedCmpAlias() {
        return cmpConfigMBean.getSelectedCmpAlias();
    }

    public boolean isViewOnly() {
        return cmpConfigMBean.isViewOnly();
    }
    
    public boolean isRaMode() {
        return getOperationalMode().equals("ra");
    }
    
    /**           CMP Authentication Modules              **/
    
    // The authentication module is different from all other fields in this page.
    // Due to legacy design, all of the has to be set at once, rather than
    // using getters & setters, in order to not overwrite value for other fields.
    private void setAuthParameters() {
        ArrayList<String> authModules = new ArrayList<>();
        ArrayList<String> authParams = new ArrayList<>();
        
        if (hmacSelected && hmacSharedSecret) {
            authModules.add(CmpConfiguration.AUTHMODULE_HMAC);
            authParams.add("-");
        } else if (hmacSelected && !hmacSharedSecret) {
            authModules.add(CmpConfiguration.AUTHMODULE_HMAC);
            authParams.add(hmacParam);
        }

        if (!isRaMode() && eeCertSelected) {
            authModules.add(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
            authParams.add("-");
        } else if (isRaMode() && eeCertSelected && !getResponseProtection().equals("pbe")) {
            authModules.add(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
            authParams.add(selectedIssuerCa);
        }
        
        if (regTokenPwdSelected && !isRaMode()) {
            authModules.add(CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD);
            authParams.add("-");
        }
        
        if (!isRaMode() && dnPartPwdSelected) {
            authModules.add(CmpConfiguration.AUTHMODULE_DN_PART_PWD);
            authParams.add(selectedDnField);
        }
        
        cmpConfiguration.setAuthenticationProperties(getSelectedCmpAlias(), authModules, authParams);
    }
    
    private void initAuthModule() {
        final String hmacAuthParam = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_HMAC, getSelectedCmpAlias());
        final String eeCertParam = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, getSelectedCmpAlias());
        final String dnPartPwdParam = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_DN_PART_PWD, getSelectedCmpAlias());
        
        hmacSelected = cmpConfiguration.isInAuthModule(getSelectedCmpAlias(), CmpConfiguration.AUTHMODULE_HMAC);
        eeCertSelected = cmpConfiguration.isInAuthModule(getSelectedCmpAlias(), CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        regTokenPwdSelected = cmpConfiguration.isInAuthModule(getSelectedCmpAlias(), CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD);
        dnPartPwdSelected = cmpConfiguration.isInAuthModule(getSelectedCmpAlias(), CmpConfiguration.AUTHMODULE_DN_PART_PWD);
        
        hmacParam = hmacAuthParam;
        if (hmacAuthParam.isEmpty() || hmacAuthParam.equals("-")) {
            hmacSharedSecret = true;
            hmacParam = "";
        }
        if (!StringUtils.isEmpty(eeCertParam)) {
            selectedIssuerCa = eeCertParam;
        }
        if (!StringUtils.isEmpty(dnPartPwdParam)) {
            selectedDnField = dnPartPwdParam;
        }
    }
    
    public void setHmacSelected(final boolean hmacSelected) {
       this.hmacSelected = hmacSelected;
    }
    
    public boolean isHmacSelected() {
        return hmacSelected;
    }
    
    public void setHmacSecret(final String hmacSecret) {
        this.hmacParam = hmacSecret;
    }
    
    public String getHmacSecret() {
        return hmacParam;
    }

    public void setHmacSecretMode(final String mode) {
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
        return StringUtils.isEmpty(selectedIssuerCa) ? String.valueOf(getCaNameSelectItems().get(0).getValue()) : selectedIssuerCa;
    }

    public void setSelectedIssuerCa(final String selectedIssuerCa) {
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
        return StringUtils.isEmpty(selectedDnField) ? String.valueOf(getDnFieldSelectItems().get(0).getValue()) : selectedDnField;
    }

    public void setSelectedDnField(final String selectedDnField) {
        this.selectedDnField = selectedDnField;
    }
    
    /**
     * @param mode 'client' or 'ra'
     */
    public void setOperationalMode(final String mode) {
        if (mode.equals("ra")) {
            cmpConfiguration.setRAMode(getSelectedCmpAlias(), true);
        } else {
            cmpConfiguration.setRAMode(getSelectedCmpAlias(), false);
            setResponseProtection("signature");
        }
    }
    
    // Not convenient way of toggling boolean, though required due to limitations with <h:selectOneRadio>
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
    
    public void setSelectedUsernameComponent(final String component) {
        cmpConfiguration.setExtractUsernameComponent(getSelectedCmpAlias(), component);
    }
    
    public String getSelectedUsernameComponent() {
        String current = cmpConfiguration.getExtractUsernameComponent(getSelectedCmpAlias());
        return StringUtils.isEmpty(current) ? String.valueOf(getExtUsernameComponentSelectItems().get(0).getValue()) : current;
    }
    
    public void setRaNameGenPrefix(final String prefix) {
        cmpConfiguration.setRANameGenPrefix(getSelectedCmpAlias(), prefix);
    }
    
    public String getRaNameGenPrefix() {
        return cmpConfiguration.getRANameGenPrefix(getSelectedCmpAlias());
    }

    public void setRaNameGenPostfix(final String prefix) {
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
  
    public String getVendorCa() {
        return cmpConfiguration.getVendorCA(getSelectedCmpAlias());
    }
    
    public void setSelectedVendorCa(final String selectedVendorCa) {
        this.selectedVendorCa = selectedVendorCa;
    }

    public String getSelectedVendorCa() {
        return selectedVendorCa == null ? String.valueOf(getVendorCaSelectItems().get(0).getValue()) : selectedVendorCa;
    }

    public void actionAddVendorCa() {
        final String currentVendorCas = cmpConfiguration.getVendorCA(getSelectedCmpAlias());
        List<String> currentVendorCaList = new ArrayList<String>();
        if (StringUtils.isNotBlank(currentVendorCas)) {
            currentVendorCaList = new ArrayList<>(Arrays.asList( currentVendorCas.split(";"))); 
        }
        if (!currentVendorCaList.contains(getSelectedVendorCa())) {
            currentVendorCaList.add(getSelectedVendorCa());
        }
        cmpConfiguration.setVendorCA(getSelectedCmpAlias(), StringUtils.join(currentVendorCaList, ";"));
    }
    
    public void actionRemoveVendorCa() {
        final String currentVendorCas = cmpConfiguration.getVendorCA(getSelectedCmpAlias());
        if (StringUtils.isNotBlank(currentVendorCas)) {
            final List<String> currentVendorCaList = new ArrayList<>(Arrays.asList( currentVendorCas.split(";")));
            if (currentVendorCaList.remove(getSelectedVendorCa())) {
                cmpConfiguration.setVendorCA(getSelectedCmpAlias(), StringUtils.join(currentVendorCaList, ";"));
            }
        }
    }
    
    /**           RA mode                                               **/
    
    public void setAllowRaVerifyPopo(final boolean allow) {
        cmpConfiguration.setAllowRAVerifyPOPO(getSelectedCmpAlias(), allow);
    }
    
    public boolean getAllowRaVerifyPopo() {
        return cmpConfiguration.getAllowRAVerifyPOPO(getSelectedCmpAlias());
    }

    public void setRaNameGenScheme(final String scheme) {
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
    
    public void setRaNameGenParams(final String params) {
        cmpConfiguration.setRANameGenParams(getSelectedCmpAlias(), params);
    }
    
    public String getRaNameGenParams() {
        return cmpConfiguration.getRANameGenParams(getSelectedCmpAlias());
    }

    public String getSelectedRaNameSchemeDnPart() {
        return selectedRaNameSchemeDnPart == null ? dnfields.get(0) : selectedRaNameSchemeDnPart;
    }

    public void setSelectedRaNameSchemeDnPart(final String selectedRaNameSchemeDnPart) {
        this.selectedRaNameSchemeDnPart = selectedRaNameSchemeDnPart;
    }
    
    public void setRaPwdGenParams(final String password) {
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
    
    public void setRaEeProfile(final String profile) {
        cmpConfiguration.setRAEEProfile(getSelectedCmpAlias(), profile);
    }
    
    public String getRaEeProfile() {
        return cmpConfiguration.getRAEEProfile(getSelectedCmpAlias());
    }
    
    public void setRaCertProfile(final String profile) {
        cmpConfiguration.setRACertProfile(getSelectedCmpAlias(), profile);
    }
    
    public String getRaCertProfile() {
        return cmpConfiguration.getRACertProfile(getSelectedCmpAlias());
    }
    
    public void setRaCaName(final String caName) {
        cmpConfiguration.setRACAName(getSelectedCmpAlias(), caName);
    }
    
    public String getRaCaName() {
        return cmpConfiguration.getRACAName(getSelectedCmpAlias());
    }
    
    /**           Response Configuration                           **/
    
    /**
     * @param mode 'pbe' or 'signature'
     */
    public void setResponseProtection(final String mode) {
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

    public void setSelectedCmpResponseAdditionalCaCert(final String selectedCmpResponseAdditionalCaCert) {
        this.selectedCmpResponseAdditionalCaCert = selectedCmpResponseAdditionalCaCert;
    }
    
    public String getSelectedCmpResponseAdditionalCaCert() {
        return selectedCmpResponseAdditionalCaCert == null ? 
                String.valueOf(getAdditionalCaCertSelectItems().get(0).getValue()) : selectedCmpResponseAdditionalCaCert;
    }
    
    public String getSelectedCmpResponseAdditionalCaCertList() throws NumberFormatException, AuthorizationDeniedException {
        final String responseCaPubsCaList = cmpConfiguration.getResponseCaPubsCA(getSelectedCmpAlias());
        return getEjbcaWebBean().getCaNamesString(responseCaPubsCaList);
    }
    
    public void actionAddCmpResponseAdditionalCaCert() {
        final String responseCaPubsCaList = cmpConfiguration.getResponseCaPubsCA(getSelectedCmpAlias());
        List<String> newResponseCaPubsCaList = new ArrayList<String>();
        if (StringUtils.isNotBlank(responseCaPubsCaList)) {
            newResponseCaPubsCaList = new ArrayList<>(Arrays.asList(responseCaPubsCaList.split(";")));
        }
        if (!newResponseCaPubsCaList.contains(getSelectedCmpResponseAdditionalCaCert())) {
            newResponseCaPubsCaList.add(getSelectedCmpResponseAdditionalCaCert());
        }
        cmpConfiguration.setResponseCaPubsCA(getSelectedCmpAlias(), StringUtils.join(newResponseCaPubsCaList, ";"));
    }
    
    public void actionRemoveCmpResponseAdditionalCaCert() {
        final String responseCaPubsCaList = cmpConfiguration.getResponseCaPubsCA(getSelectedCmpAlias());
        if (StringUtils.isNotBlank(responseCaPubsCaList)) {
            final List<String> list = new ArrayList<>(Arrays.asList(responseCaPubsCaList.split(";")));
            if (list.remove(getSelectedCmpResponseAdditionalCaCert())) {
                cmpConfiguration.setResponseCaPubsCA(getSelectedCmpAlias(), StringUtils.join(list, ";"));
            }
        }
    }

    public void setSelectedPkiResponseAdditionalCaCert(final String selectedPkiResponseAdditionalCaCert) {
        this.selectedPkiResponseAdditionalCaCert = selectedPkiResponseAdditionalCaCert;
    }
    
    public String getSelectedPkiResponseAdditionalCaCert() {
        return selectedPkiResponseAdditionalCaCert == null ? 
                String.valueOf(getAdditionalCaCertSelectItems().get(0).getValue()) : selectedPkiResponseAdditionalCaCert;
    }
    
    public String getSelectedPkiResponseAdditionalCaCertList() throws NumberFormatException, AuthorizationDeniedException {
        final String responseCaExtraCertsCaList = cmpConfiguration.getResponseExtraCertsCA(getSelectedCmpAlias());
        return getEjbcaWebBean().getCaNamesString(responseCaExtraCertsCaList);
    }
    
    public void actionAddPkiResponseAdditionalCaCert() {
        final String cas = cmpConfiguration.getResponseExtraCertsCA(getSelectedCmpAlias());
        List<String> list = new ArrayList<String>();
        if (StringUtils.isNotBlank(cas)) {
            list = new ArrayList<>(Arrays.asList(cas.split(";")));
        }
        if (!list.contains(getSelectedPkiResponseAdditionalCaCert())) {
            list.add(getSelectedPkiResponseAdditionalCaCert());
        }
        cmpConfiguration.setResponseExtraCertsCA(getSelectedCmpAlias(), StringUtils.join(list, ";"));
    }
    
    public void actionRemovePkiResponseAdditionalCaCert() {
        final String cas = cmpConfiguration.getResponseExtraCertsCA(getSelectedCmpAlias());
        if (StringUtils.isNotBlank(cas)) {
            final List<String> list = new ArrayList<>(Arrays.asList(cas.split(";")));
            if (list.remove(getSelectedPkiResponseAdditionalCaCert())) {
                    cmpConfiguration.setResponseExtraCertsCA(getSelectedCmpAlias(), StringUtils.join(list, ";"));
            }
        }
    }
    
    public String getResponseConfigDefaultCa() {
        String current = cmpConfiguration.getCMPDefaultCA(getSelectedCmpAlias());
        for (String caName : getEjbcaWebBean().getCANames().keySet()) {
            if (caSession.getCaSubjectDn(caName).equals(current)) {
                return caName;
            }
        }
        return getEjbcaWebBean().getText("CMPDEFAULTCA_DISABLED");
    }
    
    public void setResponseConfigDefaultCa(final String ca) {
        if (ca.equals(getEjbcaWebBean().getText("CMPDEFAULTCA_DISABLED")) || StringUtils.isEmpty(ca)) {
            cmpConfiguration.setCMPDefaultCA(getSelectedCmpAlias(), "");
        } else {
            cmpConfiguration.setCMPDefaultCA(getSelectedCmpAlias(), caSession.getCaSubjectDn(ca));
        }
    }
    
    public boolean isAllowAutoKeyUpdate() {
        return cmpConfiguration.getKurAllowAutomaticUpdate(getSelectedCmpAlias());
    }
    
    public void setAllowAutoKeyUpdate(final boolean allow) {
        cmpConfiguration.setKurAllowAutomaticUpdate(getSelectedCmpAlias(), allow);
    }
    
    public boolean isAllowCertRenewalSameKeys() {
        return cmpConfiguration.getKurAllowSameKey(getSelectedCmpAlias());
    }
    
    public void setAllowCertRenewalSameKeys(final boolean allow) {
        cmpConfiguration.setKurAllowSameKey(getSelectedCmpAlias(), allow);
    }
    
    public boolean isAllowServerGenKeys() {
        return cmpConfiguration.getAllowServerGeneratedKeys(getSelectedCmpAlias());
    }
    
    public void setAllowServerGenKeys(final boolean allow) {
        cmpConfiguration.setAllowServerGeneratedKeys(getSelectedCmpAlias(), allow);
    }
    
    public String getTrustedCertsPath() {
        return cmpConfiguration.getRACertPath(getSelectedCmpAlias());
    }
    
    public void setTrustedCertsPath(final String path) {
        cmpConfiguration.setRACertPath(getSelectedCmpAlias(), path);
    }
    
    public boolean isOmitVerificationsInEec() {
        return cmpConfiguration.getOmitVerificationsInEEC(getSelectedCmpAlias());
    }
    
    public void setOmitVerificationsInEec(final boolean omit) {
        cmpConfiguration.setOmitVerificationsInECC(getSelectedCmpAlias(), omit);
    }
}
