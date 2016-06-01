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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.SessionScoped;
import javax.faces.component.UIComponent;
import javax.faces.component.UIInput;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.event.ValueChangeEvent;

import org.apache.log4j.Logger;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Managed bean that backs up the enrollingmakenewrequest.xhtml page
 * 
 * @version $Id$
 */
@ManagedBean
@SessionScoped
public class EnrollMakeNewRequestBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EnrollMakeNewRequestBean.class);
    private static final String PEM_CSR_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----";
    private static final String PEM_CSR_END = "-----END CERTIFICATE REQUEST-----";

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value = "#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;

    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }

    @ManagedProperty(value = "#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;

    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    //1. Authorized end entity profiles (certificate types)
    private IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = new IdNameHashMap<EndEntityProfile>();
    private IdNameHashMap<CertificateProfile> authorizedCertificateProfiles = new IdNameHashMap<>();
    private IdNameHashMap<CAInfo> authorizedCAInfos = new IdNameHashMap<CAInfo>();
    private String selectedEndEntityProfile;
    private boolean endEntityProfileChanged;
    private Map<String, String> availableEndEntityProfiles = new HashMap<String, String>();

    //2. Available certificate profiles (certificate subtypes)
    private Map<String, String> availableCertificateProfiles = new HashMap<String, String>();
    private String selectedCertificateProfile;
    private boolean certificateProfileChanged;

    //3. Available Certificate Authorities
    private Map<String, String> availableCertificateAuthorities = new HashMap<String, String>();
    private String selectedCertificateAuthority;
    private boolean certificateAuthorityChanged;

    //4. Key-pair generation
    public enum KeyPairGeneration {
        ON_SERVER("Generated on server"), PROVIDED_BY_USER("Provided by user");
        private String value;

        private KeyPairGeneration(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    private Map<String, KeyPairGeneration> availableKeyPairGenerations = new HashMap<String, KeyPairGeneration>();
    private String selectedKeyPairGeneration;
    private boolean keyPairGenerationChanged;

    //5. Key-pair generation on server
    private Map<String, String> availableAlgorithms = new TreeMap<String, String>();
    private String selectedAlgorithm;
    private boolean algorithmChanged;
    private String certificateRequest;

    public enum TokenDownloadType {
        PEM(1), PEM_FULL_CHAIN(2), PKCS7(3), P12(4), JKS(5), DER(6);
        private int value;

        private TokenDownloadType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    //6. Certificate data
    private SubjectDn subjectDn;
    private SubjectAlternativeName subjectAlternativeName;
    private SubjectDirectoryAttributes subjectDirectoryAttributes;
    private boolean certificateDataReady;

    //7. Download credentials data
    private EndEntityInformation endEntityInformation;
    private String confirmPassword;
    public enum DownloadCredentialsType {
        NO_CREDENTIALS_DIRECT_DOWNLOAD("No credentials (direct download)"), USERNAME_PASSWORD("Username and password credentials"), REQUEST_ID(
                "RequestID");
        private String value;

        private DownloadCredentialsType(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }
    private Map<String, DownloadCredentialsType> availableDownloadCredentials = new HashMap<String, DownloadCredentialsType>();
    private String selectedDownloadCredentialsType;
    private boolean downloadCredentialsChanged;
    
    //8. Request data
    private int requestId;

    @PostConstruct
    private void postContruct() {
        initAll();
    }

    public void initAll() {
        initAuthorizedEndEntityProfiles();
        if (availableEndEntityProfiles.size() == 1) {
            setSelectedEndEntityProfile(availableEndEntityProfiles.keySet().iterator().next());
            selectEndEntityProfile();
        }
    }

    //-----------------------------------------------------------
    //All init* methods should contain ONLY application logic 

    public void initAuthorizedEndEntityProfiles() {
        setAuthorizedEndEntityProfiles(raMasterApiProxyBean.getAuthorizedEndEntityProfiles(raAuthenticationBean.getAuthenticationToken()));
        setAuthorizedCertificateProfiles(raMasterApiProxyBean.getAuthorizedCertificateProfiles(raAuthenticationBean.getAuthenticationToken()));
        setAuthorizedCAInfos(raMasterApiProxyBean.getAuthorizedCAInfos(raAuthenticationBean.getAuthenticationToken()));

        for (IdNameHashMap<EndEntityProfile>.Tuple tuple : authorizedEndEntityProfiles.values()) {
            availableEndEntityProfiles.put(tuple.getName(), tuple.getName());
        }
    }

    private void initAvailableCertificateProfiles() {
        EndEntityProfile endEntityProfile = getEndEntityProfile();
        if (endEntityProfile == null) {
            return;
        }
        String[] availableCertificateProfileIds = endEntityProfile.getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
        for (String id : availableCertificateProfileIds) {
            IdNameHashMap<CertificateProfile>.Tuple tuple = authorizedCertificateProfiles.get(Integer.parseInt(id));
            if (tuple != null) {
                String defaultCertProfileId = endEntityProfile.getValue(EndEntityProfile.DEFAULTCERTPROFILE, 0);
                if (id.equalsIgnoreCase(defaultCertProfileId)) {
                    availableCertificateProfiles.put(tuple.getName(), tuple.getName() + " (default)");
                } else {
                    availableCertificateProfiles.put(tuple.getName(), tuple.getName());
                }
            }
        }
    }

    private void initAvailableCertificateAuthorities() {
        //Get all available CAs from the selected EEP
        EndEntityProfile endEntityProfile = getEndEntityProfile();
        if (endEntityProfile == null) {
            return;
        }
        String[] availableCAsFromEEPArray = endEntityProfile.getValue(EndEntityProfile.AVAILCAS, 0).split(EndEntityProfile.SPLITCHAR);
        boolean anyCAAvailableFromEEP = availableCAsFromEEPArray.length == 1 && availableCAsFromEEPArray[0].equalsIgnoreCase(SecConst.ALLCAS + "");

        //Get all available CAs from the selected CP
        CertificateProfile certificateProfile = getCertificateProfile();
        if (certificateProfile == null) {
            return;
        }
        List<Integer> availableCAsFromCP = certificateProfile.getAvailableCAs();
        boolean anyCAAvailableFromCP = availableCAsFromCP.size() == 1 && availableCAsFromCP.iterator().next() == CertificateProfile.ANYCA;

        //Intersect both with authorized CAs
        for (IdNameHashMap<CAInfo>.Tuple tuple : authorizedCAInfos.values()) {
            if ((anyCAAvailableFromEEP || Arrays.asList(availableCAsFromEEPArray).contains(tuple.getId() + ""))
                    && (anyCAAvailableFromCP || availableCAsFromCP.contains(tuple.getId()))) {
                String defaultCAId = endEntityProfile.getValue(EndEntityProfile.DEFAULTCA, 0);
                if (!defaultCAId.isEmpty() && tuple.getId() == Integer.parseInt(defaultCAId)) {
                    availableCertificateAuthorities.put(tuple.getName(), tuple.getName() + " (default)");
                } else {
                    availableCertificateAuthorities.put(tuple.getName(), tuple.getName());
                }
            }
        }
    }

    private void initAvailableKeyPairGeneration() {
        EndEntityProfile endEntityProfile = getEndEntityProfile();
        if (endEntityProfile == null) {
            return;
        }
        String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        if (availableKeyStores.contains(SecConst.TOKEN_SOFT_P12 + "") || availableKeyStores.contains(SecConst.TOKEN_SOFT_JKS + "")
                || availableKeyStores.contains(SecConst.TOKEN_SOFT_PEM + "")) {
            availableKeyPairGenerations.put(KeyPairGeneration.ON_SERVER.getValue(), KeyPairGeneration.ON_SERVER);
        }
        if (availableKeyStores.contains(SecConst.TOKEN_SOFT_BROWSERGEN + "")) {
            availableKeyPairGenerations.put(KeyPairGeneration.PROVIDED_BY_USER.getValue(), KeyPairGeneration.PROVIDED_BY_USER);
        }
    }

    private void initAvailableAndAlgorithms() {
        CertificateProfile certificateProfile = getCertificateProfile();
        final List<String> availableKeyAlgorithms = certificateProfile.getAvailableKeyAlgorithmsAsList();
        final List<Integer> availableBitLengths = certificateProfile.getAvailableBitLengthsAsList();
        if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_DSA)) {
            for (final int availableBitLength : availableBitLengths) {
                if (availableBitLength == 1024) {
                    availableAlgorithms.put(AlgorithmConstants.KEYALGORITHM_DSA + "_" + availableBitLength,
                            AlgorithmConstants.KEYALGORITHM_DSA + " " + availableBitLength + " bits");
                }
            }
        }
        if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_RSA)) {
            for (final int availableBitLength : availableBitLengths) {
                if (availableBitLength >= 1024) {
                    availableAlgorithms.put(AlgorithmConstants.KEYALGORITHM_RSA + "_" + availableBitLength,
                            AlgorithmConstants.KEYALGORITHM_RSA + " " + availableBitLength + " bits");
                }
            }
        }
        if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
            final Set<String> ecChoices = new HashSet<>();
            final Map<String, List<String>> namedEcCurvesMap = AlgorithmTools.getNamedEcCurvesMap(false);
            if (certificateProfile.getAvailableEcCurvesAsList().contains(CertificateProfile.ANY_EC_CURVE)) {
                final String[] keys = namedEcCurvesMap.keySet().toArray(new String[namedEcCurvesMap.size()]);
                for (final String ecNamedCurve : keys) {
                    if (CertificateProfile.ANY_EC_CURVE.equals(ecNamedCurve)) {
                        continue;
                    }
                    final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(ecNamedCurve);
                    if (availableBitLengths.contains(Integer.valueOf(bitLength))) {
                        ecChoices.add(ecNamedCurve);
                    }
                }
            }
            ecChoices.addAll(certificateProfile.getAvailableEcCurvesAsList());
            ecChoices.remove(CertificateProfile.ANY_EC_CURVE);
            final List<String> ecChoicesList = new ArrayList<>(ecChoices);
            Collections.sort(ecChoicesList);
            for (final String ecNamedCurve : ecChoicesList) {
                availableAlgorithms.put(AlgorithmConstants.KEYALGORITHM_ECDSA + "_" + ecNamedCurve, AlgorithmConstants.KEYALGORITHM_ECDSA + " "
                        + StringTools.getAsStringWithSeparator(" / ", namedEcCurvesMap.get(ecNamedCurve)));
            }
        }
        for (final String algName : CesecoreConfiguration.getExtraAlgs()) {
            if (availableKeyAlgorithms.contains(CesecoreConfiguration.getExtraAlgTitle(algName))) {
                for (final String subAlg : CesecoreConfiguration.getExtraAlgSubAlgs(algName)) {
                    final String name = CesecoreConfiguration.getExtraAlgSubAlgName(algName, subAlg);
                    final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(name);
                    if (availableBitLengths.contains(Integer.valueOf(bitLength))) {
                        availableAlgorithms.put(CesecoreConfiguration.getExtraAlgTitle(algName) + "_" + name,
                                CesecoreConfiguration.getExtraAlgSubAlgTitle(algName, subAlg));
                    } else {
                        if (log.isTraceEnabled()) {
                            log.trace("Excluding " + name + " from enrollment options since bit length " + bitLength + " is not available.");
                        }
                    }
                }
            }
        }
    }

    private void initCsrUpload() {
        certificateRequest = PEM_CSR_BEGIN + "\n...base 64 encoded request...\n" + PEM_CSR_END;
    }

    private void initCertificateData() {
        EndEntityProfile endEntityProfile = getEndEntityProfile();
        if (endEntityProfile == null) {
            return;
        }

        subjectDn = new SubjectDn(endEntityProfile);
        subjectAlternativeName = new SubjectAlternativeName(endEntityProfile);
        subjectDirectoryAttributes = new SubjectDirectoryAttributes(endEntityProfile);

        //If PROVIDED BY USER key generation is selected, keyAlg and keySpec have to be extracted and Subject DN fields could be parsed from CSR
        if (selectedKeyPairGeneration != null && selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.PROVIDED_BY_USER.getValue())) {
            PKCS10CertificationRequest pkcs10CertificateRequest = CertTools.getCertificateRequestFromPem(certificateRequest); //pkcs10CertificateRequest will not be null at this point
            List<String> subjectDnFieldsFromParsedCsr = CertTools.getX500NameComponents(pkcs10CertificateRequest.getSubject().toString());
            for (String subjectDnField : subjectDnFieldsFromParsedCsr) {
                String[] nameValue = subjectDnField.split("=");
                if (nameValue != null && nameValue.length == 2) {
                    Integer dnId = DnComponents.getDnIdFromDnName(nameValue[0]);
                    if (dnId != null) {
                        String profileName = DnComponents.dnIdToProfileName(dnId);
                        if (profileName != null) {
                            EndEntityProfile.FieldInstance fieldInstance = subjectDn.getFieldInstancesMap().get(profileName);
                            if (fieldInstance != null) {
                                fieldInstance.setValue(nameValue[1]);
                                subjectDn.getFieldInstancesMap().put(profileName, fieldInstance);
                                if (log.isDebugEnabled()) {
                                    log.debug(raLocaleBean.getMessage("enroll_subject_dn_field_successfully_parsed_from_csr", subjectDnField));
                                }
                                continue;
                            }
                        }
                    }
                }
                log.info(raLocaleBean.getMessage("enroll_unparsable_subject_dn_field_from_csr", subjectDnField));
            }
            subjectDn.update();
        }
    }

    private void initDownloadCredentialsType() {
        //TODO if approval is required show only request id option or other, otherwise
        availableDownloadCredentials.put(DownloadCredentialsType.NO_CREDENTIALS_DIRECT_DOWNLOAD.getValue(),
                DownloadCredentialsType.NO_CREDENTIALS_DIRECT_DOWNLOAD);
        availableDownloadCredentials.put(DownloadCredentialsType.USERNAME_PASSWORD.getValue(), DownloadCredentialsType.USERNAME_PASSWORD);
        availableDownloadCredentials.put(DownloadCredentialsType.REQUEST_ID.getValue(), DownloadCredentialsType.REQUEST_ID);
    }

    private void initDownloadCredentialsData() {
        endEntityInformation = new EndEntityInformation();
    }

    //-----------------------------------------------------------------------------------------------
    // Helpers and get*Rendered() methods
    public String getSubjectDnFieldOutputName(String keyName) {
        return raLocaleBean.getMessage("subject_dn_" + keyName);
    }

    public String getSubjectAlternativeNameFieldOutputName(String keyName) {
        return raLocaleBean.getMessage("subject_alternative_name_" + keyName);
    }

    public String getSubjectDirectoryAttributesFieldOutputName(String keyName) {
        return raLocaleBean.getMessage("subject_directory_attributes_" + keyName);
    }

    public boolean getCsrUploadRendered() {
        return selectedKeyPairGeneration != null && selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.PROVIDED_BY_USER.getValue());
    }

    public boolean getUsernameRendered() {
        return selectedDownloadCredentialsType != null
                && selectedDownloadCredentialsType.equalsIgnoreCase(DownloadCredentialsType.USERNAME_PASSWORD.getValue());
    }

    public boolean getPasswordRendered() {
        return getUsernameRendered();
    }

    public boolean getEmailRendered() {
        return selectedDownloadCredentialsType != null
                && !selectedDownloadCredentialsType.equalsIgnoreCase(DownloadCredentialsType.NO_CREDENTIALS_DIRECT_DOWNLOAD.getValue());
    }

    public boolean getGenerateJksButtonRendered() {
        EndEntityProfile endEntityProfile = getEndEntityProfile();
        if (endEntityProfile == null) {
            return false;
        }
        String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        return selectedDownloadCredentialsType != null
                && availableKeyStores.contains(SecConst.TOKEN_SOFT_JKS + "")
                && selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.ON_SERVER.getValue());//TODO probably will need to get updated once approvals are implemented in kickassra
    }

    public boolean getGenerateP12ButtonRendered() {
        EndEntityProfile endEntityProfile = getEndEntityProfile();
        if (endEntityProfile == null) {
            return false;
        }
        String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        return selectedDownloadCredentialsType != null
                && availableKeyStores.contains(SecConst.TOKEN_SOFT_P12 + "")
                && selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.ON_SERVER.getValue());//TODO probably will need to get updated once approvals are implemented in kickassra
    }

    public boolean getGenerateFromCsrButtonRendered() {
        EndEntityProfile endEntityProfile = getEndEntityProfile();
        if (endEntityProfile == null) {
            return false;
        }
        String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        return selectedDownloadCredentialsType != null
                && availableKeyStores.contains(EndEntityConstants.TOKEN_USERGEN + "")
                && selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.PROVIDED_BY_USER.getValue());//TODO probably will need to get updated once approvals are implemented in kickassra
    }

    public boolean getNextButtonRendered() {
        return !getGenerateJksButtonRendered() && !getGenerateP12ButtonRendered() && !getGenerateFromCsrButtonRendered();
    }

    //-----------------------------------------------------------------------------------------------
    //All reset* methods should be able to clear/reset states that have changed during init* methods.
    //Always make sure that reset methods are chained!

    public final void reset() {
        availableEndEntityProfiles.clear();
        selectedEndEntityProfile = null;
        endEntityProfileChanged = false;
        resetCertificateProfile();

        initAll();
    }

    private final void resetCertificateProfile() {
        availableCertificateProfiles.clear();
        selectedCertificateProfile = null;
        certificateProfileChanged = false;

        resetCertificateAuthority();
    }

    private final void resetCertificateAuthority() {
        availableCertificateAuthorities.clear();
        selectedCertificateAuthority = null;
        certificateAuthorityChanged = false;

        resetKeyPairGeneration();
    }

    private final void resetKeyPairGeneration() {
        availableKeyPairGenerations.clear();
        selectedKeyPairGeneration = null;
        keyPairGenerationChanged = false;

        resetAlgorithmCsrUpload();
    }

    private final void resetAlgorithmCsrUpload() {
        availableAlgorithms.clear();
        selectedAlgorithm = null;
        algorithmChanged = false;
        certificateRequest = null;

        resetCertificateData();
    }

    private final void resetCertificateData() {
        subjectDn = null;
        subjectAlternativeName = null;
        subjectDirectoryAttributes = null;
        certificateDataReady = false;

        resetDownloadCredentialsType();
    }

    private final void resetDownloadCredentialsType() {
        availableDownloadCredentials.clear();
        selectedDownloadCredentialsType = null;

        resetDownloadCredentialsData();
    }

    private final void resetDownloadCredentialsData() {
        endEntityInformation = null;
        setRequestId(0);
    }

    /**
     * Proceeds to a next step of enrollment phase. In situations where AJAX is provided this method is not needed and used.
     * This method can be invoked with "Next" button.
     * @throws IOException
     */
    public final void next() throws IOException {
        if (endEntityProfileChanged) {
            selectEndEntityProfile();
        } else if (certificateProfileChanged) {
            selectCertificateProfile();
        } else if (certificateAuthorityChanged) {
            selectCertificateAuthority();
        } else if (keyPairGenerationChanged) {
            selectKeyPairGeneration();
        } else if (algorithmChanged) {
            selectAlgorithm();
        } else if (downloadCredentialsChanged) {
            selectDownloadCredentialsType();
        } else {
            if (selectedDownloadCredentialsType != null) {
                selectDownloadCredentialsType();
            } else if (subjectDn != null) {
                finalizeCertificateData();
            } else if (certificateRequest != null) {
                enterCsr();
            } else if (selectedAlgorithm != null) {
                selectAlgorithm();
            } else if (selectedKeyPairGeneration != null) {
                selectKeyPairGeneration();
            } else if (selectedCertificateAuthority != null) {
                selectCertificateAuthority();
            } else if (selectedCertificateProfile != null) {
                selectCertificateProfile();
            } else {
                selectEndEntityProfile();
            }
        }
    }

    //-----------------------------------------------------------------------------------------------
    //Action methods (e.g. select*, submit*..) that are called directly from appropriate AJAX listener or from next() method

    private final void selectEndEntityProfile() {
        setEndEntityProfileChanged(false);

        resetCertificateProfile();
        initAvailableCertificateProfiles();
        if (availableCertificateProfiles.size() == 1) {
            setSelectedCertificateProfile(availableCertificateProfiles.keySet().iterator().next());
            selectCertificateProfile();
        }
    }

    private final void selectCertificateProfile() {
        setCertificateProfileChanged(false);

        resetCertificateAuthority();
        initAvailableCertificateAuthorities();
        if (availableCertificateAuthorities.size() == 1) {
            setSelectedCertificateAuthority(availableCertificateAuthorities.keySet().iterator().next());
            selectCertificateAuthority();
        }
    }

    private final void selectCertificateAuthority() {
        setCertificateAuthorityChanged(false);

        resetKeyPairGeneration();
        initAvailableKeyPairGeneration();
        if (availableKeyPairGenerations.size() == 1) {
            setSelectedKeyPairGeneration(availableKeyPairGenerations.keySet().iterator().next());
            selectKeyPairGeneration();
        }
    }

    private final void selectKeyPairGeneration() {
        setKeyPairGenerationChanged(false);

        resetAlgorithmCsrUpload();
        if (selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.ON_SERVER.getValue())) {
            initAvailableAndAlgorithms();
        } else if (selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.PROVIDED_BY_USER.getValue())) {
            initCsrUpload();
        }
    }

    private final void selectAlgorithm() {
        setAlgorithmChanged(false);

        resetCertificateData();
        initCertificateData();
        raLocaleBean.addMessageInfo("somefunction_testok", "selectedAlgorithm", selectedAlgorithm);
    }

    private final void enterCsr() {
        PKCS10CertificationRequest pkcs10CertificateRequest = CertTools.getCertificateRequestFromPem(certificateRequest);
        if (pkcs10CertificateRequest == null) {
            raLocaleBean.addMessageError("enroll_invalid_certificate_request");
            return;
        }

        resetCertificateData();
        initCertificateData();
    }

    private final void finalizeCertificateData() {
        certificateDataReady = true;

        initDownloadCredentialsType();
    }

    private final void selectDownloadCredentialsType() {
        setDownloadCredentialsChanged(false);

        resetDownloadCredentialsData();
        initDownloadCredentialsData();
    }

    private final void setDownloadCredentialsData() {
        endEntityInformation.setCAId(getCAInfo().getCAId());
        endEntityInformation.setCardNumber(""); //TODO Card Number
        endEntityInformation.setCertificateProfileId(authorizedCertificateProfiles.get(selectedCertificateProfile).getId());
        endEntityInformation.setDN(subjectDn.toString());
        endEntityInformation.setEndEntityProfileId(authorizedEndEntityProfiles.get(selectedEndEntityProfile).getId());
        endEntityInformation.setExtendedinformation(new ExtendedInformation());//TODO don't know anything about it...
        endEntityInformation.setHardTokenIssuerId(0); //TODO not sure....
        endEntityInformation.setKeyRecoverable(false); //TODO not sure...
        endEntityInformation.setPrintUserData(false); // TODO not sure...
        endEntityInformation.setSendNotification(false); // TODO will be updated
        endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityInformation.setSubjectAltName(subjectAlternativeName.toString());
        endEntityInformation.setTimeCreated(new Date());//TODO client vs server time issues?
        endEntityInformation.setTimeModified(new Date());//TODO client vs server time issues?
        endEntityInformation.setType(new EndEntityType(EndEntityTypes.ENDUSER));
        //TODO how to set subject directory attributes?
    }

    public final void addEndEntityAndGenerateCertificeDer() {
        byte[] token = addEndEntityAndGenerateToken(EndEntityConstants.TOKEN_USERGEN, "DER", TokenDownloadType.DER);
        downloadToken(token, "application/octet-stream", ".der");
    }

    public final void addEndEntityAndGenerateCertificePksc7() {
        byte[] token = addEndEntityAndGenerateToken(EndEntityConstants.TOKEN_USERGEN, "PKCS#7", TokenDownloadType.PKCS7);
        downloadToken(token, "application/octet-stream", ".p7b");
    }

    public final void addEndEntityAndGenerateCertificePemFullChain() {
        byte[] token = addEndEntityAndGenerateToken(EndEntityConstants.TOKEN_USERGEN, "PEM", TokenDownloadType.PEM_FULL_CHAIN);
        downloadToken(token, "application/octet-stream", ".pem");
    }

    public final void addEndEntityAndGenerateCertificePem() {
        byte[] token = addEndEntityAndGenerateToken(EndEntityConstants.TOKEN_USERGEN, "PEM", TokenDownloadType.PEM);
        downloadToken(token, "application/octet-stream", ".pem");
    }

    public final void addEndEntityAndGenerateP12() {
        byte[] token = addEndEntityAndGenerateToken(EndEntityConstants.TOKEN_SOFT_P12, "PKCS#12", TokenDownloadType.P12);
        downloadToken(token, "application/x-pkcs12", ".p12");
    }

    public final void addEndEntityAndGenerateJks() {
        byte[] token = addEndEntityAndGenerateToken(EndEntityConstants.TOKEN_SOFT_JKS, "JKS", TokenDownloadType.JKS);
        downloadToken(token, "application/octet-stream", ".jks");
    }

    /**
     * Adds end entity and creates its token that will be downloaded. This method is responsible for deleting the end entity if something goes wrong with token creation.
     * @param tokenType the type of the token that will be created (one of: TOKEN_USERGEN, TOKEN_SOFT_P12, TOKEN_SOFT_JKS from EndEntityConstants)
     * @param tokenName the name of the token. It will be used only in messages and logs
     * @param tokenDownloadType the download type/format of the token. This is used only with TOKEN_USERGEN since this is the only one that have different formats: PEM, DER,...)
     * @return generated token as byte array
     */
    private final byte[] addEndEntityAndGenerateToken(int tokenType, String tokenName, TokenDownloadType tokenDownloadType) {
        //Update the EndEntityInformation data
        subjectDn.update();
        subjectAlternativeName.updateValue();
        subjectDirectoryAttributes.updateValue();
        setDownloadCredentialsData();
        endEntityInformation.setTokenType(tokenType);

        //Enter temporary credentials
        if (!selectedDownloadCredentialsType.equalsIgnoreCase(DownloadCredentialsType.USERNAME_PASSWORD.getValue()) ) {
            String commonName = subjectDn.getFieldInstancesMap().get(DnComponents.COMMONNAME).getValue(); //Common Name has to be required field
            endEntityInformation.setUsername(commonName);
            endEntityInformation.setPassword(commonName);
        }

        //Add end-entity
        try {
            if (raMasterApiProxyBean.addUser(raAuthenticationBean.getAuthenticationToken(), endEntityInformation, /*clearpwd=*/false)) {
                log.info(raLocaleBean.getMessage("enroll_end_entity_has_been_successfully_added", endEntityInformation.getUsername()));
            } else {
                raLocaleBean.addMessageInfo("enroll_end_entity_could_not_be_added", endEntityInformation.getUsername());
                log.error(raLocaleBean.getMessage("enroll_end_entity_could_not_be_added", endEntityInformation.getUsername()));
                return null;
            }
        } catch (EndEntityExistsException e) {
            raLocaleBean.addMessageInfo("enroll_username_already_exists", endEntityInformation.getUsername(), e.getMessage());
            log.error(raLocaleBean.getMessage("enroll_username_already_exists", endEntityInformation.getUsername(), e.getMessage()), e);
            return null;
        } catch (AuthorizationDeniedException e) {
            raLocaleBean.addMessageInfo("enroll_unauthorized_operation", endEntityInformation.getUsername(), e.getMessage());
            log.error(raLocaleBean.getMessage("enroll_unauthorized_operation", endEntityInformation.getUsername(), e.getMessage()), e);
            return null;
        } catch (WaitingForApprovalException e) {
            requestId = e.getApprovalId();
            log.info(requestId);
            log.info(e);
            return null;
        }
        
        //End entity has been added now! Make sure clean-up is done in this "try-finally" block if something goes wrong inside it
        try{

            //Get token's algorithm from CSR (PROVIDED_BY_USER) or it can be specified directly (ON_SERVER)
            String keyAlg = null;
            String keyLength = null;
            if (selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.PROVIDED_BY_USER.getValue())) {
                PKCS10CertificationRequest pkcs10CertificateRequest = CertTools.getCertificateRequestFromPem(certificateRequest);
                if (pkcs10CertificateRequest == null) {
                    raLocaleBean.addMessageError("enroll_invalid_certificate_request");
                    return null;
                }
                JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(pkcs10CertificateRequest);
                PublicKey publicKey;
                try {
                    publicKey = jcaPKCS10CertificationRequest.getPublicKey();
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    log.warn(raLocaleBean.getMessage("enroll_csr_public_key_could_not_be_extracted"));
                    raLocaleBean.addMessageError("enroll_csr_public_key_could_not_be_extracted");
                    return null;
                }
                keyAlg = AlgorithmTools.getKeyAlgorithm(publicKey);
                keyLength = AlgorithmTools.getKeySpecification(publicKey);
            } else if (selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.ON_SERVER.getValue())) {
                final String[] tokenKeySpecSplit = selectedAlgorithm.split("_");
                keyAlg = tokenKeySpecSplit[0];
                keyLength = tokenKeySpecSplit[1];
            }
    
            //Generates a keystore token if user has specified "ON SERVER" key pair generation.
            //Generates a certificate token if user has specified "PROVIDED_BY_USER" key pair generation
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            if (selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.ON_SERVER.getValue())) {
                KeyStore keystore = null;
                try {
                    keystore = raMasterApiProxyBean.generateKeystore(raAuthenticationBean.getAuthenticationToken(), endEntityInformation);
                    log.info(raLocaleBean.getMessage("enroll_token_has_been_successfully_generated", tokenName, endEntityInformation.getUsername()));
    
                    keystore.store(buffer, endEntityInformation.getPassword().toCharArray());
                } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | AuthorizationDeniedException e) {
                    raLocaleBean.addMessageError("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage());
                    log.error(raLocaleBean.getMessage("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage()), e);
                    return null;
                } finally {
                    if (buffer != null) {
                        try {
                            buffer.close();
                        } catch (IOException e) {
                        }
                    }
                }
            } else if (selectedKeyPairGeneration.equalsIgnoreCase(KeyPairGeneration.PROVIDED_BY_USER.getValue())) {
                byte[] certificateDataToDownload = null;
                try {
                    certificateDataToDownload = raMasterApiProxyBean.createCertificate(raAuthenticationBean.getAuthenticationToken(),
                            endEntityInformation, CertTools.getCertificateRequestFromPem(certificateRequest).getEncoded());
                    if (certificateDataToDownload == null) {
                        raLocaleBean.addMessageError("enroll_certificate_could_not_be_generated", endEntityInformation.getUsername());
                        return null;
                    }
    
                    if (tokenDownloadType == TokenDownloadType.PEM_FULL_CHAIN) {
                        X509Certificate certificate = CertTools.getCertfromByteArray(certificateDataToDownload, X509Certificate.class);
                        LinkedList<Certificate> chain = new LinkedList<Certificate>(getCAInfo().getCertificateChain());
                        chain.addFirst(certificate);
                        certificateDataToDownload = CertTools.getPemFromCertificateChain(chain);
                    } else if (tokenDownloadType == TokenDownloadType.PKCS7) {
                        X509Certificate certificate = CertTools.getCertfromByteArray(certificateDataToDownload, X509Certificate.class);
                        certificateDataToDownload = raMasterApiProxyBean.createPkcs7(raAuthenticationBean.getAuthenticationToken(), certificate, true);
                        certificateDataToDownload = CertTools.getPemFromPkcs7(certificateDataToDownload);
                    } else if (tokenDownloadType == TokenDownloadType.PEM) {
                        X509Certificate certificate = CertTools.getCertfromByteArray(certificateDataToDownload, X509Certificate.class);
                        certificateDataToDownload = CertTools.getPemFromCertificateChain(Arrays.asList((Certificate) certificate));
                    }
    
                    buffer.write(certificateDataToDownload);
                } catch (CertificateParsingException | CertificateEncodingException | AuthorizationDeniedException | IOException e) {
                    raLocaleBean.addMessageError("enroll_certificate_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage());
                    log.error(raLocaleBean.getMessage("enroll_certificate_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage()),
                            e);
                    return null;
                } finally {
                    if (buffer != null) {
                        try {
                            buffer.close();
                        } catch (IOException e) {
                        }
                    }
                }
            }
    
            return buffer.toByteArray();
            
        }finally{
            //End entity clean-up must be done if enrollment could not be completed (but end-entity has been added)
            try {
                EndEntityInformation fromCA = raMasterApiProxyBean.searchUser(raAuthenticationBean.getAuthenticationToken(), endEntityInformation.getUsername());
                if(fromCA != null && fromCA.getStatus() != EndEntityConstants.STATUS_GENERATED){
                    raMasterApiProxyBean.deleteUser(raAuthenticationBean.getAuthenticationToken(), endEntityInformation.getUsername());
                }
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException(e);
            }
        }
    }
    
    private final void downloadToken(byte[] token, String responseContentType, String fileExtension) {
        if (token == null) {
            return;
        }

        //Download the token
        FacesContext fc = FacesContext.getCurrentInstance();
        ExternalContext ec = fc.getExternalContext();
        ec.responseReset(); // Some JSF component library or some Filter might have set some headers in the buffer beforehand. We want to get rid of them, else it may collide.
        ec.setResponseContentType(responseContentType);
        ec.setResponseContentLength(token.length);
        ec.setResponseHeader("Content-Disposition",
                "attachment; filename=\"" + StringTools.stripFilename(endEntityInformation.getUsername() + fileExtension) + "\""); // The Save As popup magic is done here. You can give it any file name you want, this only won't work in MSIE, it will use current request URL as file name instead.
        OutputStream output = null;
        try {
            output = ec.getResponseOutputStream();
            output.write(token);
            output.flush();
        } catch (IOException e) {
            log.error(raLocaleBean.getMessage("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage()), e);
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                }
            }
            fc.responseComplete(); // Important! Otherwise JSF will attempt to render the response which obviously will fail since it's already written with a file and closed.
        }
    }

    //-----------------------------------------------------------------------------------------------
    //Listeners that will be invoked from xhtml
    public final void endEntityProfileChangedListener(ValueChangeEvent e) {
        setEndEntityProfileChanged(true);
    }

    public final void certificateProfileChangedListener(ValueChangeEvent e) {
        setCertificateProfileChanged(true);
    }

    public final void certificateAuthorityChangedListener(ValueChangeEvent e) {
        setCertificateAuthorityChanged(true);
    }

    public final void keyPairGenerationChangedListener(ValueChangeEvent e) {
        setKeyPairGenerationChanged(true);
    }

    public final void algorithmChangedListener(ValueChangeEvent e) {
        setAlgorithmChanged(true);
    }

    public final void downloadCredentialsTypeChangedListener(ValueChangeEvent e) {
        setDownloadCredentialsChanged(true);
    }

    public final void endEntityProfileAjaxListener(final AjaxBehaviorEvent event) {
        selectEndEntityProfile();
    }

    public final void certificateProfileAjaxListener(final AjaxBehaviorEvent event) {
        selectCertificateProfile();
    }

    public final void certificateAuthorityAjaxListener(final AjaxBehaviorEvent event) {
        selectCertificateAuthority();
    }

    public final void keyPairGenerationAjaxListener(final AjaxBehaviorEvent event) {
        selectKeyPairGeneration();
    }

    public final void algorithmAjaxListener(final AjaxBehaviorEvent event) {
        selectAlgorithm();
    }

    public final void csrInputTextAjaxListener(final AjaxBehaviorEvent event) {
        enterCsr();
    }

    public final void downloadCredentialsTypeAjaxListener(final AjaxBehaviorEvent event) {
        selectDownloadCredentialsType();
    }
    
    //-----------------------------------------------------------------------------------------------
    //Validators
    
    public void validatePassword(ComponentSystemEvent event) {
        if(selectedDownloadCredentialsType != null && !selectedDownloadCredentialsType.equalsIgnoreCase(DownloadCredentialsType.USERNAME_PASSWORD.getValue())){
            return;
        }
        FacesContext fc = FacesContext.getCurrentInstance();
        UIComponent components = event.getComponent();
        UIInput uiInputPassword = (UIInput) components.findComponent("passwordField");
        String password = uiInputPassword.getLocalValue() == null ? "" : uiInputPassword.getLocalValue().toString();
        UIInput uiInputConfirmPassword = (UIInput) components.findComponent("passwordConfirmField");
        String confirmPassword = uiInputConfirmPassword.getLocalValue() == null ? "" : uiInputConfirmPassword.getLocalValue().toString();
        if (password.isEmpty() || confirmPassword.isEmpty()) {
            raLocaleBean.addMessageError(raLocaleBean.getMessage("enroll_password_can_not_be_empty"));
            fc.renderResponse();
            
        }else if (!password.equals(confirmPassword)) {
            raLocaleBean.addMessageError(raLocaleBean.getMessage("enroll_passwords_are_not_equal"));
            fc.renderResponse();
        }
    }
    
    //-----------------------------------------------------------------------------------------------
    //Automatically generated getters/setters
    /**
     * @return the authorizedEndEntityProfiles
     */
    public IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles() {
        return authorizedEndEntityProfiles;
    }

    /**
     * @param authorizedEndEntityProfiles the authorizedEndEntityProfiles to set
     */
    private void setAuthorizedEndEntityProfiles(IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles) {
        this.authorizedEndEntityProfiles = authorizedEndEntityProfiles;
    }

    /**
     * @return the selectedEndEntityProfile
     */
    public String getSelectedEndEntityProfile() {
        return selectedEndEntityProfile;
    }

    public EndEntityProfile getEndEntityProfile() {
        if (selectedEndEntityProfile == null) {
            return null;
        }
        IdNameHashMap<EndEntityProfile>.Tuple temp = authorizedEndEntityProfiles.get(selectedEndEntityProfile);
        if (temp == null) {
            return null;
        }
        return temp.getValue();
    }

    public CertificateProfile getCertificateProfile() {
        if (selectedCertificateProfile == null) {
            return null;
        }
        IdNameHashMap<CertificateProfile>.Tuple temp = authorizedCertificateProfiles.get(selectedCertificateProfile);
        if (temp == null) {
            return null;
        }
        return temp.getValue();
    }

    public CAInfo getCAInfo() {
        if (selectedCertificateAuthority == null) {
            return null;
        }
        IdNameHashMap<CAInfo>.Tuple temp = authorizedCAInfos.get(selectedCertificateAuthority);
        if (temp == null) {
            return null;
        }
        return temp.getValue();
    }

    /**
     * @param selectedEndEntityProfile the selectedEndEntityProfile to set
     */
    public void setSelectedEndEntityProfile(String selectedEndEntityProfile) {
        this.selectedEndEntityProfile = selectedEndEntityProfile;
    }

    /**
     * @return the selectedKeyPairGeneration
     */
    public String getSelectedKeyPairGeneration() {
        return selectedKeyPairGeneration;
    }

    /**
     * @param selectedKeyPairGeneration the selectedKeyPairGeneration to set
     */
    public void setSelectedKeyPairGeneration(String selectedKeyStoreGeneration) {
        this.selectedKeyPairGeneration = selectedKeyStoreGeneration;
    }

    /**
     * @return the endEntityProfileChanged
     */
    public boolean isEndEntityProfileChanged() {
        return endEntityProfileChanged;
    }

    /**
     * @param endEntityProfileChanged the endEntityProfileChanged to set
     */
    public void setEndEntityProfileChanged(boolean endEntityProfileChanged) {
        this.endEntityProfileChanged = endEntityProfileChanged;
    }

    public Map<String, KeyPairGeneration> getAvailableKeyPairGenerations() {
        return availableKeyPairGenerations;
    }

    public void setAvailableKeyPairGenerations(Map<String, KeyPairGeneration> availableKeyPairGenerations) {
        this.availableKeyPairGenerations = availableKeyPairGenerations;
    }

    /**
     * @return the keyPairGenerationChanged
     */
    public boolean isKeyPairGenerationChanged() {
        return keyPairGenerationChanged;
    }

    /**
     * @param keyPairGenerationChanged the keyPairGenerationChanged to set
     */
    public void setKeyPairGenerationChanged(boolean keyPairGenerationChanged) {
        this.keyPairGenerationChanged = keyPairGenerationChanged;
    }

    /**
     * @return the availableCertificateProfiles
     */
    public Map<String, String> getAvailableCertificateProfiles() {
        return availableCertificateProfiles;
    }

    /**
     * @param availableCertificateProfiles the availableCertificateProfiles to set
     */
    public void setAvailableCertificateProfiles(Map<String, String> availableCertificateProfiles) {
        this.availableCertificateProfiles = availableCertificateProfiles;
    }

    /**
     * @return the selectedCertificateProfile
     */
    public String getSelectedCertificateProfile() {
        return selectedCertificateProfile;
    }

    /**
     * @param selectedCertificateProfile the selectedCertificateProfile to set
     */
    public void setSelectedCertificateProfile(String selectedCertificateProfile) {
        this.selectedCertificateProfile = selectedCertificateProfile;
    }

    /**
     * @return the certificateProfileChanged
     */
    public boolean isCertificateProfileChanged() {
        return certificateProfileChanged;
    }

    /**
     * @param certificateProfileChanged the certificateProfileChanged to set
     */
    public void setCertificateProfileChanged(boolean certificateProfileChanged) {
        this.certificateProfileChanged = certificateProfileChanged;
    }

    /**
     * @return the availableAlgorithms
     */
    public Map<String, String> getAvailableAlgorithms() {
        return availableAlgorithms;
    }

    /**
     * @param availableAlgorithms the availableAlgorithms to set
     */
    public void setAvailableAlgorithms(Map<String, String> availableAlgorithms) {
        this.availableAlgorithms = availableAlgorithms;
    }

    /**
     * @return the selectedAlgorithm
     */
    public String getSelectedAlgorithm() {
        return selectedAlgorithm;
    }

    /**
     * @param selectedAlgorithm the selectedAlgorithm to set
     */
    public void setSelectedAlgorithm(String selectedAlgorithm) {
        this.selectedAlgorithm = selectedAlgorithm;
    }

    /**
     * @return the algorithmChanged
     */
    public boolean isAlgorithmChanged() {
        return algorithmChanged;
    }

    /**
     * @param algorithmChanged the algorithmChanged to set
     */
    public void setAlgorithmChanged(boolean algorithmChanged) {
        this.algorithmChanged = algorithmChanged;
    }

    /**
     * @return the endEntityInformation
     */
    public EndEntityInformation getEndEntityInformation() {
        return endEntityInformation;
    }

    /**
     * @param endEntityInformation the endEntityInformation to set
     */
    public void setEndEntityInformation(EndEntityInformation endEntityInformation) {
        this.endEntityInformation = endEntityInformation;
    }

    /**
     * @return the confirmPassword
     */
    public String getConfirmPassword() {
        return confirmPassword;
    }

    /**
     * @param confirmPassword the confirmPassword to set
     */
    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    /**
     * @return the availableCertificateAuthorities
     */
    public Map<String, String> getAvailableCertificateAuthorities() {
        return availableCertificateAuthorities;
    }

    /**
     * @param availableCertificateAuthorities the availableCertificateAuthorities to set
     */
    public void setAvailableCertificateAuthorities(Map<String, String> availableCertificateAuthorities) {
        this.availableCertificateAuthorities = availableCertificateAuthorities;
    }

    /**
     * @return the selectedCertificateAuthority
     */
    public String getSelectedCertificateAuthority() {
        return selectedCertificateAuthority;
    }

    /**
     * @param selectedCertificateAuthority the selectedCertificateAuthority to set
     */
    public void setSelectedCertificateAuthority(String selectedCertificateAuthority) {
        this.selectedCertificateAuthority = selectedCertificateAuthority;
    }

    /**
     * @return the certificateAuthorityChanged
     */
    public boolean isCertificateAuthorityChanged() {
        return certificateAuthorityChanged;
    }

    /**
     * @param certificateAuthorityChanged the certificateAuthorityChanged to set
     */
    public void setCertificateAuthorityChanged(boolean certificateAuthorityChanged) {
        this.certificateAuthorityChanged = certificateAuthorityChanged;
    }

    public IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles() {
        return authorizedCertificateProfiles;
    }

    public void setAuthorizedCertificateProfiles(IdNameHashMap<CertificateProfile> authorizedCertificateProfiles) {
        this.authorizedCertificateProfiles = authorizedCertificateProfiles;
    }

    /**
     * @return the authorizedCAInfos
     */
    public IdNameHashMap<CAInfo> getAuthorizedCAInfos() {
        return authorizedCAInfos;
    }

    /**
     * @param authorizedCAInfos the authorizedCAInfos to set
     */
    public void setAuthorizedCAInfos(IdNameHashMap<CAInfo> authorizedCAInfos) {
        this.authorizedCAInfos = authorizedCAInfos;
    }

    /**
     * @return the availableEndEntityProfiles
     */
    public Map<String, String> getAvailableEndEntityProfiles() {
        return availableEndEntityProfiles;
    }

    /**
     * @param availableEndEntityProfiles the availableEndEntityProfiles to set
     */
    public void setAvailableEndEntityProfiles(Map<String, String> availableEndEntities) {
        this.availableEndEntityProfiles = availableEndEntities;
    }

    /**
     * @return the subjectDN
     */
    public SubjectDn getSubjectDn() {
        return subjectDn;
    }

    /**
     * @param subjectDn the subjectDN to set
     */
    public void setSubjectDn(SubjectDn subjectDn) {
        this.subjectDn = subjectDn;
    }

    /**
     * @return the subjectAlternativeName
     */
    public SubjectAlternativeName getSubjectAlternativeName() {
        return subjectAlternativeName;
    }

    /**
     * @param subjectAlternativeName the subjectAlternativeName to set
     */
    public void setSubjectAlternativeName(SubjectAlternativeName subjectAlternativeName) {
        this.subjectAlternativeName = subjectAlternativeName;
    }

    /**
     * @return the subjectDirectoryAttributes
     */
    public SubjectDirectoryAttributes getSubjectDirectoryAttributes() {
        return subjectDirectoryAttributes;
    }

    /**
     * @param subjectDirectoryAttributes the subjectDirectoryAttributes to set
     */
    public void setSubjectDirectoryAttributes(SubjectDirectoryAttributes subjectDirectoryAttributes) {
        this.subjectDirectoryAttributes = subjectDirectoryAttributes;
    }

    /**
     * @return the certificateDataReady
     */
    public boolean isCertificateDataReady() {
        return certificateDataReady;
    }

    /**
     * @param certificateDataReady the certificateDataReady to set
     */
    public void setCertificateDataReady(boolean certificateDataReady) {
        this.certificateDataReady = certificateDataReady;
    }

    /**
     * @return the availableDownloadCredentials
     */
    public Map<String, DownloadCredentialsType> getAvailableDownloadCredentials() {
        return availableDownloadCredentials;
    }

    /**
     * @param availableDownloadCredentials the availableDownloadCredentials to set
     */
    public void setAvailableDownloadCredentials(Map<String, DownloadCredentialsType> availableDownloadCredentials) {
        this.availableDownloadCredentials = availableDownloadCredentials;
    }

    /**
     * @return the selectedDownloadCredentials
     */
    public String getSelectedDownloadCredentialsType() {
        return selectedDownloadCredentialsType;
    }

    /**
     * @param selectedDownloadCredentialsType the selectedDownloadCredentials to set
     */
    public void setSelectedDownloadCredentialsType(String selectedDownloadCredentialsType) {
        this.selectedDownloadCredentialsType = selectedDownloadCredentialsType;
    }

    /**
     * @return the downloadCredentialsChanged
     */
    public boolean isDownloadCredentialsChanged() {
        return downloadCredentialsChanged;
    }

    /**
     * @param downloadCredentialsChanged the downloadCredentialsChanged to set
     */
    public void setDownloadCredentialsChanged(boolean downloadCredentialsChanged) {
        this.downloadCredentialsChanged = downloadCredentialsChanged;
    }

    /**
     * @return the certificateRequest
     */
    public String getCertificateRequest() {
        return certificateRequest;
    }

    /**
     * @param certificateRequest the certificateRequest to set
     */
    public void setCertificateRequest(String certificateRequest) {
        this.certificateRequest = certificateRequest;
    }

    /**
     * @return the requestId
     */
    public int getRequestId() {
        return requestId;
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(int requestId) {
        this.requestId = requestId;
    }
}
