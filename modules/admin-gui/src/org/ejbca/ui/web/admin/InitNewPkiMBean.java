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

package org.ejbca.ui.web.admin;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.cainterface.CaInfoDto;

@ManagedBean
@SessionScoped
public class InitNewPkiMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private static final Logger log = Logger.getLogger(InitNewPkiMBean.class);
    
    private static final String CREATE_NEW_CRYPTO_TOKEN = "createNewToken";
    private static final String USE_SOFT_CRYPTO_TOKEN = "useExistingToken";
    
    private static final String DEFAULT_CA_NAME = "Management CA";
    private static final String DEFAULT_CA_DN = "CN=ManagementCA,O=EJBCA Sample,C=SE";
    private static final String DEFAULT_CA_VALIDITY = "3650";

    private List<SelectItem> availableCryptoTokenSelectItems;
    private List<SelectItem> availableSigningAlgorithmSelectItems;
    private List<String> availableCryptoTokenKeyAliases;
    private List<String> availableCryptoTokenMixedAliases;
    private List<String> availableCryptoTokenEncryptionAliases;
    
    private CaInfoDto caInfoDto = new CaInfoDto();
    private boolean suitableCryptoTokenExists;
    private boolean initNewPkiRedirect = false;
    private String cryptoTokenType;
    private int currentCryptoTokenId = 0;
    
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    
    private CAInterfaceBean caBean;
    
    public void initialize() {
//        if (!FacesContext.getCurrentInstance().isPostback())  {
//            log.info("### is not postback");
//        } else {
//            log.info("### is postback");
//        }
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            caBean = SessionBeans.getCaBean(request);
        } catch (ServletException e) {
            throw new IllegalStateException("Could not initiate CAInterfaceBean", e);
        }
        updateAvailableCryptoTokenList();
        updateAvailableSigningAlgorithmList();
        updateKeyAliases();
//        }
    }
    
    public InitNewPkiMBean() {
        super(StandardRules.ROLE_ROOT.resource());
    }
    
    public String actionNext() {
        if (getCryptoTokenType().equals(CREATE_NEW_CRYPTO_TOKEN) && !initNewPkiRedirect) {
            initNewPkiRedirect = true;
            return CREATE_NEW_CRYPTO_TOKEN;
        }
        if (verifyCaFields()) {
            return "next";
        }
        //TODO language file and perhaps describe which field...
        addErrorMessage("CA Fields Missing");
        return "";
    }
    
    public String actionBackToInstallation() {
        resetCaSelections();
        return "back";
    }
    
    public String actionBackToCaSettings() {
        resetKeyStoreSelections();
        return "back";
    }
    
    public String actionBackToKeyStoreSettings() {
        resetSuperAdminSettings();
        return "back";
    }
    
    public String actionBackToAdminSettings() {
        return "back";
    }

    public boolean isSuitableCryptoTokenExists() {
        return suitableCryptoTokenExists;
    }

    public void setSuitableCryptoTokenExists(boolean suitableCryptoTokenExists) {
        this.suitableCryptoTokenExists = suitableCryptoTokenExists;
    }

    public String getCaName() {
        return StringUtils.isEmpty(caInfoDto.getCaSubjectDN()) ? DEFAULT_CA_NAME : caInfoDto.getCaSubjectDN();
    }

    public void setCaName(String caName) {
        this.caInfoDto.setCaName(caName);
    }

    public String getCaDn() {
        return StringUtils.isEmpty(caInfoDto.getCaSubjectDN()) ? DEFAULT_CA_DN : caInfoDto.getCaSubjectDN();
    }

    public void setCaDn(String caDn) {
        this.caInfoDto.setCaSubjectDN(caDn);
    }

    public String getValidity() {
        return StringUtils.isEmpty(caInfoDto.getCaEncodedValidity()) ? DEFAULT_CA_VALIDITY : caInfoDto.getCaEncodedValidity();
    }
    
    public void setValidity(String validity) {
        caInfoDto.setCaEncodedValidity(validity);
    }
    
    public CaInfoDto getCaInfoDto() {
        return caInfoDto;
    }

    public void setCaInfoDto(CaInfoDto caInfoDto) {
        this.caInfoDto = caInfoDto;
    }
    
    public String getCryptoTokenIdParam() {
        return caInfoDto.getCryptoTokenIdParam();
    }

    public void setCryptoTokenIdParam(final String cryptoTokenIdParam) {
        caInfoDto.setCryptoTokenIdParam(cryptoTokenIdParam);
        updateKeyAliases();
    }
    
    public String getCryptoTokenType() {
        return StringUtils.isEmpty(cryptoTokenType) ? USE_SOFT_CRYPTO_TOKEN : cryptoTokenType;
    }

    public void setCryptoTokenType(String cryptoTokenType) {
        this.cryptoTokenType = cryptoTokenType;
    }

    // Read from cryptotoken.xhtml in order to determine whether an option
    // should be provided to redirect back to this page after creating a 
    // new Crypto Token.
    public boolean isInitNewPkiRedirect() {
        return initNewPkiRedirect;
    }

    public void setInitNewPkiRedirect(boolean initNewPkiRedirect) {
        this.initNewPkiRedirect = initNewPkiRedirect;
    }
    
    public boolean isRenderKeyOptions() {
        return !getAvailableCryptoTokenList().isEmpty() && 
               (isInitNewPkiRedirect() || StringUtils.equals(getCryptoTokenType(), USE_SOFT_CRYPTO_TOKEN));
    }
    
    public List<SelectItem> getAvailableSigningAlgList() {
        final List<SelectItem> resultList = new ArrayList<>();
        final String cryptoTokenIdParam = caInfoDto.getCryptoTokenIdParam();
        for (final String current : AlgorithmConstants.AVAILABLE_SIGALGS) {
            if (!AlgorithmTools.isSigAlgEnabled(current)) {
                continue; // e.g. GOST3410 if not configured
            }
            resultList.add(new SelectItem(current, current, ""));
        }
        // "0" is the first "Create a new Crypto Token..." option in the select list.
        // There is no information to filter signing algorithms by.
        if (!StringUtils.isEmpty(cryptoTokenIdParam) && !cryptoTokenIdParam.equals("0")) {
            try {
                final List<KeyPairInfo> cryptoTokenKeyPairInfos = cryptoTokenManagementSession.getKeyPairInfos(getAdmin(), Integer.parseInt(cryptoTokenIdParam));
                return resultList.stream()
                                 .filter(sa -> isSigningAlgorithmApplicableForCryptoToken(sa.getLabel(), cryptoTokenKeyPairInfos))
                                 .collect(Collectors.toList());
            } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
                log.error("Crypto token key pair infos could not be fetched.", e);
            }
        }
        return resultList;
    }
    
    public List<SelectItem> getAvailableCryptoTokenList() {
        return availableCryptoTokenSelectItems;
    }
    
    public List<SelectItem> getKeyAliasesList(final String keyType) {
        final List<SelectItem> resultList = new ArrayList<>();
        switch (keyType) {
        case "defaultKey":
            for (final String alias : availableCryptoTokenMixedAliases) {
                resultList.add(new SelectItem(alias, alias));
            }
            return resultList;
        case "certSignKey":
        case "testKey":
            for (final String alias : availableCryptoTokenKeyAliases) {
                resultList.add(new SelectItem(alias, alias));
            }
            return resultList;
        case "keyEncryptKey":
            for (final String alias : availableCryptoTokenEncryptionAliases) {
                resultList.add(new SelectItem(alias, alias));
            }
            return resultList;
        default:
            return Collections.emptyList();
        }
    }

    public List<SelectItem> getKeyAliasesListWithDefault(final String keyType) {
        final List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        resultList.addAll(getKeyAliasesList(keyType));
        return resultList;
    }
    
    /** KeyStore Methods **/
    
    private String serverHostName = "localhost";
    private String serverDn = "CN=localhost,O=EJBCA Sample,C=SE";
    private String serverAltName = "dnsName=localhost,IPAddress=127.0.0.1";
    private String keyStorePassword;
    private String keyStorePasswordRepeated;
    
    
    public String getServerHostName() {
        return serverHostName;
    }

    public void setServerHostName(String serverHostName) {
        this.serverHostName = serverHostName;
    }

    public String getServerDn() {
        return serverDn;
    }

    public void setServerDn(String serverDn) {
        this.serverDn = serverDn;
    }
    
    public String getServerAltName() {
        return serverAltName;
    }

    public void setServerAltName(String serverAltName) {
        this.serverAltName = serverAltName;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getKeyStorePasswordRepeated() {
        return keyStorePasswordRepeated;
    }

    public void setKeyStorePasswordRepeated(String keyStorePasswordRepeated) {
        this.keyStorePasswordRepeated = keyStorePasswordRepeated;
    }

    /** SuperAdmin Methods **/
    
    private String adminDn = "CN=SuperAdmin";
    private String adminValidity = "730";
    private String adminKeyStorePassword;
    private String adminKeyStorePasswordRepeated;
    
    public String getAdminDn() {
        return adminDn;
    }

    public void setAdminDn(String adminDn) {
        this.adminDn = adminDn;
    }

    public String getAdminValidity() {
        return adminValidity;
    }

    public void setAdminValidity(String adminValidity) {
        this.adminValidity = adminValidity;
    }

    public String getAdminKeyStorePassword() {
        return adminKeyStorePassword;
    }

    public void setAdminKeyStorePassword(String adminKeyStorePassword) {
        this.adminKeyStorePassword = adminKeyStorePassword;
    }

    public String getAdminKeyStorePasswordRepeated() {
        return adminKeyStorePasswordRepeated;
    }

    public void setAdminKeyStorePasswordRepeated(String adminKeyStorePasswordRepeated) {
        this.adminKeyStorePasswordRepeated = adminKeyStorePasswordRepeated;
    }

    /** Private Methods **/
    
    private boolean isSigningAlgorithmApplicableForCryptoToken(String signingAlgorithm, List<KeyPairInfo> cryptoTokenKeyPairInfos) {
        String requiredKeyAlgorithm = AlgorithmTools.getKeyAlgorithmFromSigAlg(signingAlgorithm);
        for (final KeyPairInfo cryptoTokenKeyPairInfo : cryptoTokenKeyPairInfos) {
            if (requiredKeyAlgorithm.equals(cryptoTokenKeyPairInfo.getKeyAlgorithm())) {
                return true;
            }
        }
        return false;
    }
    
    private void updateAvailableSigningAlgorithmList() {
        availableSigningAlgorithmSelectItems = getAvailableSigningAlgList();

        // Update caInfoDTO with a default algorithm
        if (StringUtils.isEmpty(caInfoDto.getSignatureAlgorithmParam()) && availableSigningAlgorithmSelectItems.size() > 0){
            caInfoDto.setSignatureAlgorithmParam(availableSigningAlgorithmSelectItems.get(0).getLabel());
        }
    }
    
    private void updateAvailableCryptoTokenList() {
        // Defaults if an error occurs
        suitableCryptoTokenExists = true;
        availableCryptoTokenSelectItems = Collections.emptyList();
        try {
            List<Entry<String, String>> availableCryptoTokens = caBean.getAvailableCryptoTokens(true);
            suitableCryptoTokenExists = !availableCryptoTokens.isEmpty();
            final List<SelectItem> resultList = new ArrayList<>();
            int numSelected = 0; // should be 1 after the loop
            for (final Entry<String, String> entry : availableCryptoTokens) {
                // Ensure that we have a default for the next section
                if (caInfoDto.getCryptoTokenIdParam() == null || caInfoDto.getCryptoTokenIdParam().length() == 0) {
                    caInfoDto.setCryptoTokenIdParam(entry.getKey());
                }

                final boolean selectCurrent = entry.getKey().equals(caInfoDto.getCryptoTokenIdParam());
                numSelected += selectCurrent ? 1 : 0;
                if (currentCryptoTokenId == 0 || selectCurrent) {
                    currentCryptoTokenId = Integer.parseInt(entry.getKey());
                }
                resultList.add(new SelectItem(entry.getKey(), entry.getValue(), ""));
            }
            if (numSelected == 0) {
                resultList.add(new SelectItem(caInfoDto.getCryptoTokenIdParam(), "-" + getEjbcaWebBean().getText("CRYPTOTOKEN_MISSING_OR_EMPTY") + " "
                        + caInfoDto.getCryptoTokenIdParam() + "-"));
                caInfoDto.setCryptoTokenIdParam(null);
                currentCryptoTokenId = 0;
            }
            availableCryptoTokenSelectItems = resultList;
        } catch (final AuthorizationDeniedException e) {
            log.error("Error while listing available CryptoTokens!", e);
        }
    }
    
    private void updateAvailableKeyAliasesList() throws CryptoTokenOfflineException, AuthorizationDeniedException {
        final List<KeyPairInfo> keyPairInfos = caBean.getKeyPairInfos(currentCryptoTokenId);
        availableCryptoTokenKeyAliases = caBean.getAvailableCryptoTokenAliases(keyPairInfos, caInfoDto.getSignatureAlgorithmParam());
        availableCryptoTokenMixedAliases = caBean.getAvailableCryptoTokenMixedAliases(keyPairInfos, caInfoDto.getSignatureAlgorithmParam());
        availableCryptoTokenEncryptionAliases = caBean.getAvailableCryptoTokenEncryptionAliases(keyPairInfos, caInfoDto.getSignatureAlgorithmParam());
    }
    
    private void updateKeyAliases() {
        if (caInfoDto.getCryptoTokenIdParam() != null && caInfoDto.getCryptoTokenIdParam().length() > 0 && Integer.parseInt(caInfoDto.getCryptoTokenIdParam()) != 0) {
            currentCryptoTokenId = Integer.parseInt(caInfoDto.getCryptoTokenIdParam());
        }
        availableCryptoTokenKeyAliases = new ArrayList<>(); // Avoids NPE in getters if the code below fails.
        availableCryptoTokenMixedAliases = new ArrayList<>();
        availableCryptoTokenEncryptionAliases = new ArrayList<>();
        if (currentCryptoTokenId != 0) {
            try {
                // List of key aliases is needed even on Edit CA page, to show the renew key dropdown list
                updateAvailableKeyAliasesList();
                setDefaultKeyAliases();
            } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
                log.error("Error while listing crypto token key aliases!", e);
            }
        }
    }
    
    private void setDefaultKeyAliases() {
        // Make up defaults based on key alias names
        caInfoDto.setSelectedKeyEncryptKey("");
        caInfoDto.setTestKey("");

        for (final String alias : availableCryptoTokenEncryptionAliases) {
            if (CAToken.SOFTPRIVATEDECKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "default")) {
                caInfoDto.setCryptoTokenDefaultKey(alias);
            } else if (CAToken.SOFTPRIVATESIGNKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "sign")) {
                caInfoDto.setCryptoTokenCertSignKey(alias);
            } else if (StringUtils.containsIgnoreCase(alias, "test")) {
                caInfoDto.setTestKey(alias);
            }
        }

        for (final String alias : availableCryptoTokenKeyAliases) {
            if (CAToken.SOFTPRIVATEDECKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "default")) {
                caInfoDto.setCryptoTokenDefaultKey(alias);
            } else if (CAToken.SOFTPRIVATESIGNKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "sign"))  {
                caInfoDto.setCryptoTokenCertSignKey(alias);
            } else if (StringUtils.containsIgnoreCase(alias, "test")) {
                caInfoDto.setTestKey(alias);
            }
        }
    }
    
    private boolean verifyCaFields() {
        // TODO check if all CA fields are valid before continuing
        return true;
    }
    
    private void resetCaSelections() {
        cryptoTokenType = null;
        currentCryptoTokenId = 0;
        initNewPkiRedirect = false;
        availableCryptoTokenSelectItems = null;
        availableSigningAlgorithmSelectItems = null;
        availableCryptoTokenKeyAliases = null;
        availableCryptoTokenMixedAliases = null;
        availableCryptoTokenEncryptionAliases = null;
        this.caInfoDto = new CaInfoDto();
    }
    
    private void resetKeyStoreSelections() {
        keyStorePassword = null;
        keyStorePasswordRepeated = null;
    }
    
    private void resetSuperAdminSettings() {
        adminKeyStorePassword = null;
        adminKeyStorePasswordRepeated = null;
    }
}
