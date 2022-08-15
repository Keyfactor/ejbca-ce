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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.stream.Collectors;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSession;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.CertificateSignatureException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.cainterface.CaInfoDto;

@ManagedBean
@SessionScoped
public class InitNewPkiMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private static final Logger log = Logger.getLogger(InitNewPkiMBean.class);
    
    private static final String APPLICATION_X_PKCS12 = "application/x-pkcs12";
    private static final String CREATE_NEW_CRYPTO_TOKEN = "createNewToken";
    private static final String USE_EXISTING_CRYPTO_TOKEN = "useExistingToken";
    private static final String DEFAULT_CA_NAME = "ManagementCA";
    private static final String DEFAULT_CA_DN = "CN=ManagementCA,O=EJBCA Sample,C=SE";
    private static final String DEFAULT_CA_VALIDITY = "10y";

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
    private boolean installed = false;
    private boolean deletePublicRole = true;
    
    @EJB
    private AuthorizationSystemSessionLocal authorizationSystemSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private KeyStoreCreateSessionLocal keyStoreCreateSession;
    @EJB
    private RoleSessionLocal roleSession;
    
    private CAInterfaceBean caBean;
    
    public void initialize() {
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            caBean = SessionBeans.getCaBean(request);
        } catch (ServletException e) {
            throw new IllegalStateException("Could not initiate CAInterfaceBean", e);
        }
        updateAvailableCryptoTokenList();
        updateAvailableSigningAlgorithmList();
        updateKeyAliases();
    }
    
    public InitNewPkiMBean() {
        super(StandardRules.ROLE_ROOT.resource());
        if (StringUtils.isEmpty(caInfoDto.getSignatureAlgorithmParam())) {
            caInfoDto.setSignatureAlgorithmParam(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        }
    }
    
    public String actionNextGoToInitAdmin() {
        // Redirect to Crypto Token page if 'Create New..' is selected and we haven't been there yet, 
        // or if we have been there but yet no tokens exists.
        if (getCryptoTokenType().equals(CREATE_NEW_CRYPTO_TOKEN) && (!initNewPkiRedirect || getAvailableCryptoTokenList().isEmpty())) {
            initNewPkiRedirect = true;
            // After redirect, go back to "Use existing" (assuming that one was created)
            setCryptoTokenType(USE_EXISTING_CRYPTO_TOKEN);
            return CREATE_NEW_CRYPTO_TOKEN;
        }
        if (verifyCaFields()) {
            return "next";
        }
        return "";
    }
    
    public String actionNextGoToSummary() {
        if (verifySuperAdminFields()) {
            return "next";
        }
        return "";
    }
    
    public String actionBackToInstallation() {
        resetCaSelections();
        return "back";
    }
    
    public String actionBackToCaSettings() {
        resetSuperAdminSettings();
        return "back";
    }
    
    public String actionBackToAdminSettings() {
        return "back";
    }

    public boolean isSuitableCryptoTokenExists() {
        return suitableCryptoTokenExists;
    }
    
    public boolean isInstalled() {
        return installed;
    }

    public void setSuitableCryptoTokenExists(boolean suitableCryptoTokenExists) {
        this.suitableCryptoTokenExists = suitableCryptoTokenExists;
    }

    public String getCaName() {
        return StringUtils.isEmpty(caInfoDto.getCaName()) ? DEFAULT_CA_NAME : caInfoDto.getCaName();
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
    
    public String getCertificateValidityHelp() {
        return getEjbcaWebBean().getText("DATE_HELP") + "=" + getEjbcaWebBean().getDateExample() + "." + getEjbcaWebBean().getText("YEAR365DAYS")
            + ", " + getEjbcaWebBean().getText("MO30DAYS");
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

    public String getSelectedCryptoTokenName() {
        return cryptoTokenManagementSession.getCryptoToken(currentCryptoTokenId).getTokenName();
    }
    
    public void setCryptoTokenIdParam(final String cryptoTokenIdParam) {
        caInfoDto.setCryptoTokenIdParam(cryptoTokenIdParam);
        updateKeyAliases();
    }
    
    public String getCryptoTokenType() {
        if (StringUtils.isEmpty(cryptoTokenType)) {
            setCryptoTokenType(USE_EXISTING_CRYPTO_TOKEN);
            return USE_EXISTING_CRYPTO_TOKEN;
        }
        return cryptoTokenType;
    }

    public void setCryptoTokenType(String cryptoTokenType) {
        this.cryptoTokenType = cryptoTokenType;
    }

    public boolean isDeletePublicRole() {
        return deletePublicRole;
    }

    public void setDeletePublicRole(boolean deletePublicRole) {
        this.deletePublicRole = deletePublicRole;
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
    
    public boolean isCryptoTokenAvailable() {
        return !isRenderKeyOptions() && getCryptoTokenType().equals(USE_EXISTING_CRYPTO_TOKEN);
    }
    
    public boolean isRenderKeyOptions() {
        return !getAvailableCryptoTokenList().isEmpty() && StringUtils.equals(getCryptoTokenType(), USE_EXISTING_CRYPTO_TOKEN);
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
    

    /** SuperAdmin Methods **/

    private String adminDn = "CN=SuperAdmin";
    private String adminValidity = "2y";
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
    
    public String getCaCertificateDownloadLink() {
        return getEjbcaWebBean().getBaseUrl() + getEjbcaWebBean().getGlobalConfiguration().getCaPath() + "/cafunctions.xhtml";
    }
    
    public void install() {
        try {
            createCa();
        } catch (CAExistsException e) {
            addErrorMessage("CAALREADYEXISTS", getCaName());
            log.error("CA " + getCaName() + " already exists.");
            return;
        } catch (CryptoTokenOfflineException e) {
            addErrorMessage("CATOKENISOFFLINE");
            log.error("Crypto token was unavailable: " + e.getMessage());
            return;
        } catch (InvalidAlgorithmException e) {
            log.error("Algorithm was not valid: " + e.getMessage());
            addErrorMessage("INVALIDSIGORKEYALGPARAM");
            return;
        } catch (AuthorizationDeniedException e) {
            addErrorMessage("ACCESSRULES_ERROR_UNAUTH", getAdmin() + " not authorized to create CA");
            log.error("Not authorized to create CA: " + e.getMessage());
            return;
        }
        if (isDeletePublicRole()) {
            try {
                roleSession.deleteRoleIdempotent(getAdmin(), null, AuthorizationSystemSession.PUBLIC_ACCESS_ROLE);
            } catch (AuthorizationDeniedException e) {
                addErrorMessage("ACCESSRULES_ERROR_UNAUTH", getAdmin() + " not authorized to delete role");
                log.error("Not authorized to delete role: " + e.getMessage());
                return;
            }
        }
        installed = true;
    }
    
    public void enrollSuperAdmin() throws CADoesntExistsException, CustomFieldException, IllegalNameException, ApprovalException,
            CertificateSerialNumberException, AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException {
        byte[] keyStore = null;
        try {
            keyStore = createSuperAdmin();
        } catch (EndEntityExistsException | CertificateCreateException e) {
            addErrorMessage("SuperAdmin already exists. In order to re-enroll keystore. edit the end enttiy, change status to 'New' and try again.");
            return;
        } catch (Exception e) {
            log.info("SuperAdmin Keystore could not be generated", e);
            addErrorMessage("SuperAdmin Keystore could not be generated");
            return;
        }
        downloadP12(keyStore);
    }
    
    /** Private Methods **/

    private void downloadP12(byte[] token) {
        //Download the token
        FacesContext fc = FacesContext.getCurrentInstance();
        ExternalContext ec = fc.getExternalContext();
        ec.responseReset(); 
        ec.setResponseContentType(APPLICATION_X_PKCS12);
        ec.setResponseContentLength(token.length);
        final String fileName = getFileName();
        ec.setResponseHeader("Content-Disposition", "attachment; filename=\"" + fileName + ".p12" + "\"");
        try (final OutputStream output = ec.getResponseOutputStream()) {
            output.write(token);
            output.flush();
            fc.responseComplete();
        } catch (IOException e) {
            addErrorMessage("DOWNLOAD_FAILED", fileName);
            log.info("Token " + fileName + " could not be downloaded", e);
        }
    }

    private byte[] createSuperAdmin() throws AuthorizationDeniedException, CADoesntExistsException, EndEntityExistsException, CustomFieldException, 
            IllegalNameException, ApprovalException, CertificateSerialNumberException, EndEntityProfileValidationException, WaitingForApprovalException, 
            CertificateEncodingException, KeyStoreException, InvalidAlgorithmParameterException, IllegalKeyException, CertificateCreateException, CertificateRevokeException, 
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CustomCertificateSerialNumberException, AuthStatusException, 
            AuthLoginException, NoSuchEndEntityException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateSignatureException {
        final CAInfo caInfo = caSession.getCAInfo(getAdmin(), getCaName());
        final int caId = caInfo.getCAId();
        endEntityManagementSession.addUser(getAdmin(), "superadmin", getAdminKeyStorePassword(), getAdminDn(), 
                null, null, false, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, 
                new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.TOKEN_SOFT_P12, caId);
        Date notAfter = ValidityDate.getDate(getAdminValidity(), new Date(), caInfo.isExpirationInclusive());
        KeyStore keyStore = null;
        keyStore = keyStoreCreateSession.generateOrKeyRecoverToken(getAdmin(), "superadmin", getAdminKeyStorePassword(), 
                caId, "2048", "RSA", new Date(), notAfter, SecConst.TOKEN_SOFT_P12, false, false, false, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
        
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            keyStore.store(outputStream, getAdminKeyStorePassword().toCharArray());
            return outputStream.toByteArray();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            log.error(e); 
        }
        return ArrayUtils.EMPTY_BYTE_ARRAY;
    }
    
    private void createCa() throws CAExistsException, CryptoTokenOfflineException, InvalidAlgorithmException, AuthorizationDeniedException {
        final String encodedValidity = getValidity();        
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, caInfoDto.getCryptoTokenDefaultKey());
        if (!StringUtils.isEmpty(caInfoDto.getCryptoTokenCertSignKey())) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
        }
        if (!StringUtils.isEmpty(caInfoDto.getCryptoTokenCertSignKey())) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
        }
        if (!StringUtils.isEmpty(caInfoDto.getSelectedKeyEncryptKey())) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, caInfoDto.getSelectedKeyEncryptKey());
        }
        if (!StringUtils.isEmpty(caInfoDto.getTestKey())) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, caInfoDto.getTestKey());
        }
        // Create the CA Token
        final CAToken caToken = new CAToken(currentCryptoTokenId, caTokenProperties);
        caToken.setSignatureAlgorithm(caInfoDto.getSignatureAlgorithmParam());
        caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        
        // Add CA Services
        String keyType = AlgorithmConstants.KEYALGORITHM_RSA;
        String extendedServiceKeySpec = caInfoDto.getSignatureAlgorithmParam();
        if (extendedServiceKeySpec.startsWith("DSA")) {
            keyType = AlgorithmConstants.KEYALGORITHM_DSA;
        } else if (extendedServiceKeySpec.startsWith(AlgorithmConstants.KEYSPECPREFIX_ECGOST3410)) {
            keyType = AlgorithmConstants.KEYALGORITHM_ECGOST3410;
        } else if (AlgorithmTools.isDstu4145Enabled() && extendedServiceKeySpec.startsWith(CesecoreConfiguration.getOidDstu4145())) {
            keyType = AlgorithmConstants.KEYALGORITHM_DSTU4145;
        } else {
            keyType = AlgorithmConstants.KEYALGORITHM_ECDSA;
        }
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<>();
        if (keyType.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
            // Never use larger keys than 2048 bit RSA for OCSP signing
            int len = Integer.parseInt(extendedServiceKeySpec);
            if (len > 2048) {
                extendedServiceKeySpec = "2048";
            }
        }
        extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=CmsCertificate, " + getCaDn(), "",
                extendedServiceKeySpec, keyType));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        X509CAInfo caInfo = createX509CaInfo(getCaDn(), null, getCaName(), CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, encodedValidity, 
                CAInfo.SELFSIGNED, caToken, null, extendedcaservices);
        
        caAdminSession.createCA(getAdmin(), caInfo);
        authorizationSystemSession.initializeAuthorizationModuleWithSuperAdmin(getAdmin(), getCaDn().hashCode(),
                CertTools.getCommonNameFromSubjectDn(getAdminDn()));
        
    }
    
    private X509CAInfo createX509CaInfo(String dn, String subjectAltName, String caname, int certificateProfileId, String validityString, int signedByCAId, CAToken catokeninfo,
            List<CertificatePolicy> policies, List<ExtendedCAServiceInfo> extendedcaservices) {
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(dn, caname, CAConstants.CA_ACTIVE, certificateProfileId, validityString,
                signedByCAId, new ArrayList<Certificate>(), catokeninfo);
        cainfo.setSubjectAltName(subjectAltName);
        cainfo.setCertificateChain(new ArrayList<Certificate>());
        cainfo.setEncodedValidity(getValidity());
        cainfo.setPolicies(policies);
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        cainfo.setDeltaCRLPeriod(0 * SimpleTime.MILLISECONDS_PER_HOUR);
        cainfo.setCaSerialNumberOctetSize(CesecoreConfiguration.getSerialNumberOctetSizeForNewCa());
        return cainfo;
    }
    
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
        if (StringUtils.isEmpty(caInfoDto.getSignatureAlgorithmParam()) && !availableSigningAlgorithmSelectItems.isEmpty()) {
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
    
    private String getFileName() {
        final String commonName = CertTools.getPartFromDN(getAdminDn(), "CN");
        if (StringUtils.isEmpty(commonName)) {
            return "certificatetoken";
        }
        if (StringUtils.isAsciiPrintable(commonName)) {
            return StringTools.stripFilename(commonName);
        }
        return Base64.encodeBase64String(commonName.getBytes());
    }
    
    private boolean verifySuperAdminFields() {
        if (StringUtils.isEmpty(getAdminKeyStorePassword()) ||
                !StringUtils.equals(getAdminKeyStorePassword(), getAdminKeyStorePasswordRepeated())) {
            addErrorMessage("PASSWORDSDOESNTMATCH");
            return false;
        }
        if (StringUtils.isEmpty(getAdminDn())) {
            addErrorMessage("SUBJECTDNINVALID");
            return false;
        }
        return true;
    }
    
    private boolean verifyCaFields() {
        if (StringUtils.isEmpty(getCryptoTokenIdParam())) {
            addErrorMessage("CRYPTOTOKEN_MISSING_OR_EMPTY");
            return false;
        }
        if (StringUtils.isEmpty(caInfoDto.getCaName()) || StringUtils.isEmpty(caInfoDto.getCaSubjectDN())) {
            addErrorMessage("CA_NAME_EMPTY");
            return false;
        }
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
    
    private void resetSuperAdminSettings() {
        adminKeyStorePassword = null;
        adminKeyStorePasswordRepeated = null;
    }
}
