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
package org.ejbca.ui.web.admin.cryptotoken;

import java.io.File;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.AvailableCryptoToken;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.Pkcs11SlotLabel;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.util.KeyTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.util.SlotList;

/**
 * JavaServer Faces Managed Bean for managing CryptoTokens.
 * Session scoped and will cache the list of tokens and keys.
 * 
 * @version $Id$
 */
public class CryptoTokenMBean extends BaseManagedBean implements Serializable {

    private static final String CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX = "CRYPTOTOKEN_LABEL_TYPE_";
    
    /** GUI table representation of a CryptoToken that can be interacted with. */
    public class CryptoTokenGuiInfo {
        private final CryptoTokenInfo cryptoTokenInfo;
        private final String p11LibraryAlias;
        private final boolean allowedActivation;
        private final boolean allowedDeactivation;
        private String authenticationCode;
        private final boolean referenced;
        
        private CryptoTokenGuiInfo(CryptoTokenInfo cryptoTokenInfo, String p11LibraryAlias, boolean allowedActivation, boolean allowedDectivation, boolean referenced) {
            this.cryptoTokenInfo = cryptoTokenInfo;
            this.p11LibraryAlias = p11LibraryAlias;
            this.allowedActivation = allowedActivation;
            this.allowedDeactivation = allowedDectivation;
            this.referenced = referenced;
        }
        
        public String getStatusImg() {
            return getEjbcaWebBean().getImagefileInfix(isActive()?"status-ca-active.png":"status-ca-offline.png");
        }
        public String getAutoActivationYesImg() {
            return getEjbcaWebBean().getImagefileInfix("status-ca-active.png");
        }
        public Integer getCryptoTokenId() { return cryptoTokenInfo.getCryptoTokenId(); }
        public String getTokenName() { return cryptoTokenInfo.getName(); }
        public boolean isActive() { return cryptoTokenInfo.isActive(); }
        public boolean isAutoActivation() { return cryptoTokenInfo.isAutoActivation(); }
        public String getTokenType() { return cryptoTokenInfo.getType(); }
        
        /**
         * @return A string representing slot:index:label for a P11 slot
         */
        public String getP11Slot() { return cryptoTokenInfo.getP11Slot(); }
        public String getP11SlotLabelType() { return cryptoTokenInfo.getP11SlotLabelType(); }
        public String getP11SlotLabelTypeText() {
            if (!isP11SlotType()) {
                return "";
            }
            return EjbcaJSFHelper.getBean().getText().get(CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX + cryptoTokenInfo.getP11SlotLabelType());
        }
        public String getP11LibraryAlias() { return p11LibraryAlias; }
        public String getAuthenticationCode() { return authenticationCode; }
        public void setAuthenticationCode(String authenticationCode) { this.authenticationCode = authenticationCode; }
        public boolean isAllowedActivation() { return allowedActivation; }
        public boolean isAllowedDeactivation() { return allowedDeactivation; }
        public boolean isReferenced() { return referenced; }
        public boolean isP11SlotType() { return PKCS11CryptoToken.class.getSimpleName().equals(cryptoTokenInfo.getType()); }
    }

    /** GUI edit/view representation of a CryptoToken that can be interacted with. */
    public class CurrentCryptoTokenGuiInfo {
        private String name = "";
        private String type = SoftCryptoToken.class.getSimpleName();
        private String secret1 = "";
        private String secret2 = "";
        private boolean autoActivate = false;
        private boolean allowExportPrivateKey = false;
        private String p11Library = "";
        private String p11Slot = WebConfiguration.getDefaultP11SlotNumber();
        private Pkcs11SlotLabelType p11SlotLabelType = Pkcs11SlotLabelType.SLOT_NUMBER;
        private String p11AttributeFile = "default";
        private boolean active = false;
        private boolean referenced = false;
        private String keyPlaceholders;
        
        private CurrentCryptoTokenGuiInfo() {}
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getSecret1() { return secret1; }
        public void setSecret1(String secret1) { this.secret1 = secret1; }
        public String getSecret2() { return secret2; }
        public void setSecret2(String secret2) { this.secret2 = secret2; }
        public boolean isAutoActivate() { return autoActivate; }
        public void setAutoActivate(boolean autoActivate) { this.autoActivate = autoActivate; }
        public boolean isAllowExportPrivateKey() { return allowExportPrivateKey; }
        public void setAllowExportPrivateKey(boolean allowExportPrivateKey) { this.allowExportPrivateKey = allowExportPrivateKey; }
        public String getP11Library() { return p11Library; }
        public void setP11Library(String p11Library) { this.p11Library = p11Library; }
        public String getP11Slot() { return p11Slot; }
        public void setP11Slot(String p11Slot) { this.p11Slot = p11Slot; }
        public String getP11SlotLabelType() { return p11SlotLabelType.getKey(); }
        public void setP11SlotLabelType(String p11SlotLabelType) {
            this.p11SlotLabelType = Pkcs11SlotLabelType.getFromKey(p11SlotLabelType);
        }
        public String getP11SlotLabelTypeText() {
            return EjbcaJSFHelper.getBean().getText().get(CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX + getP11SlotLabelType());
        }
        public String getP11AttributeFile() { return p11AttributeFile; }
        public void setP11AttributeFile(String p11AttributeFile) { this.p11AttributeFile = p11AttributeFile; }
        public boolean isActive() { return active; }
        public void setActive(boolean active) { this.active = active; }
        public boolean isReferenced() { return referenced; }
        public void setReferenced(boolean referenced) { this.referenced = referenced; }
        public String getKeyPlaceholders() { return keyPlaceholders; }
        public void setKeyPlaceholders(String keyTemplates) { this.keyPlaceholders = keyTemplates; }

        public String getP11LibraryAlias() { return CryptoTokenMBean.this.getP11LibraryAlias(p11Library); }
        public String getP11AttributeFileAlias() { return CryptoTokenMBean.this.getP11AttributeFileAlias(p11AttributeFile); }
        public boolean isShowSoftCryptoToken() {
            return SoftCryptoToken.class.getSimpleName().equals(getType());
        }

        public boolean isShowP11CryptoToken() {
            return PKCS11CryptoToken.class.getSimpleName().equals(getType());
        }

        public boolean isSlotOfTokenLabelType() {
            return p11SlotLabelType.equals(Pkcs11SlotLabelType.SLOT_LABEL);
        }
    }
    
    /** Selectable key pair GUI representation */
    public class KeyPairGuiInfo {
        private final String alias;
        private final String keyAlgorithm;
        private final String keySpecification; // to be displayed in GUI
        private final String rawKeySpec; // to be used for key generation
        private final String subjectKeyID;
        private final boolean placeholder;
        private boolean selected = false;
        
        private KeyPairGuiInfo(KeyPairInfo keyPairInfo) {
            alias = keyPairInfo.getAlias();
            keyAlgorithm = keyPairInfo.getKeyAlgorithm();
            rawKeySpec = keyPairInfo.getKeySpecification();
            if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyPairInfo.getKeyAlgorithm())) {
                keySpecification = getEcKeySpecAliases(rawKeySpec);
            } else {
                keySpecification = rawKeySpec;
            }
            subjectKeyID = keyPairInfo.getSubjectKeyID();
            placeholder = false;
        }
        
        /**
         * Creates a placeholder with a template string, in the form of "alias;keyspec".
         * Placeholders are created in CryptoTokens that are imported from Statedump. 
         */
        private KeyPairGuiInfo(String templateString) {
            String[] pieces = templateString.split("["+CryptoToken.KEYPLACEHOLDERS_INNER_SEPARATOR+"]");
            alias = pieces[0];
            keyAlgorithm = KeyTools.keyspecToKeyalg(pieces[1]);
            rawKeySpec = KeyTools.shortenKeySpec(pieces[1]);
            if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlgorithm)) {
                keySpecification = getEcKeySpecAliases(rawKeySpec);
            } else {
                keySpecification = rawKeySpec;
            }
            subjectKeyID = "";
            placeholder = true;
        }
        
        public String getAlias() { return alias; }
        public String getKeyAlgorithm() { return keyAlgorithm; }
        public String getKeySpecification() { return keySpecification; }
        public String getRawKeySpec() { return rawKeySpec; }
        public String getSubjectKeyID() { return subjectKeyID; }
        public boolean isPlaceholder() { return placeholder; }
        
        public boolean isSelected() { return selected; }
        public void setSelected(boolean selected) { this.selected = selected; }
    }

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CryptoTokenMBean.class);

    private List<CryptoTokenGuiInfo> cryptoTokenGuiInfos = new ArrayList<CryptoTokenGuiInfo>();
    @SuppressWarnings("rawtypes") //JDK6 does not support typing for ListDataModel
    private ListDataModel cryptoTokenGuiList = null;
    private List<KeyPairGuiInfo> keyPairGuiInfos = new ArrayList<KeyPairGuiInfo>();
    @SuppressWarnings("rawtypes") //JDK6 does not support typing for ListDataModel
    private ListDataModel keyPairGuiList = null;
    private String keyPairGuiListError = null;
    private int currentCryptoTokenId = 0;
    private CurrentCryptoTokenGuiInfo currentCryptoToken = null;
    private boolean currentCryptoTokenEditMode = true;  // currentCryptoTokenId==0 from start

    private final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = getEjbcaWebBean().getEjb().getCryptoTokenManagementSession();
    private final AccessControlSessionLocal accessControlSession = getEjbcaWebBean().getEjb().getAccessControlSession();
    private final AuthenticationToken authenticationToken = getAdmin();
    private final CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
    private final InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession = getEjbcaWebBean().getEjb().getInternalKeyBindingMgmtSession();

    /** Workaround to cache the items used to render the page long enough for actions to be able to use them, but reload on every page view. */
    public boolean isPageLoadResetTrigger() {
        flushCaches();
        return false;
    }

    /** Force reload from underlying (cache) layer */
    private void flushCaches() {
        cryptoTokenGuiList = null;
        flushCurrent();
    }
    
    /** Force reload from underlying (cache) layer for the current CryptoToken and its list of key pairs */
    private void flushCurrent() {
        keyPairGuiList = null;
        currentCryptoToken = null;
    }
    
    /** @return a List of all CryptoToken Identifiers referenced by CAs. */
    private List<Integer> getReferencedCryptoTokenIds() {
        final List<Integer> ret = new ArrayList<Integer>();
        // Add all CryptoToken ids referenced by CAs
        for (int caId : caSession.getAllCaIds()) {
            try {
                ret.add(Integer.valueOf(caSession.getCAInfoInternal(caId).getCAToken().getCryptoTokenId()));
            } catch (CADoesntExistsException e) {
                log.warn("Referenced CA has suddenly disappearded unexpectedly. caid=" + caId);
            }
        }
        // Add all CryptoToken ids referenced by InternalKeyBindings
        for (final String internalKeyBindingType : internalKeyBindingMgmtSession.getAvailableTypesAndProperties().keySet()) {
            for (final InternalKeyBindingInfo internalKeyBindingInfo : internalKeyBindingMgmtSession.getAllInternalKeyBindingInfos(internalKeyBindingType)) {
                ret.add(Integer.valueOf(internalKeyBindingInfo.getCryptoTokenId()));
            }
        }
        // In the future other components that use CryptoTokens should be checked here as well!
        return ret;
    }
    
    /** Build a list sorted by name from the authorized cryptoTokens that can be presented to the user */
    @SuppressWarnings({ "rawtypes", "unchecked" }) //JDK6 does not support typing for ListDataModel
    public ListDataModel getCryptoTokenGuiList() throws AuthorizationDeniedException {
        if (cryptoTokenGuiList==null) {
            final List<Integer> referencedCryptoTokenIds = getReferencedCryptoTokenIds();
            final List<CryptoTokenGuiInfo> list = new ArrayList<CryptoTokenGuiInfo>();
            for (final CryptoTokenInfo cryptoTokenInfo : cryptoTokenManagementSession.getCryptoTokenInfos(authenticationToken)) {
                final String p11LibraryAlias = getP11LibraryAlias(cryptoTokenInfo.getP11Library());
                final boolean allowedActivation = accessControlSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.ACTIVATE + "/" + cryptoTokenInfo.getCryptoTokenId().toString());
                final boolean allowedDeactivation = accessControlSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.DEACTIVATE + "/" + cryptoTokenInfo.getCryptoTokenId().toString());
                final boolean referenced = referencedCryptoTokenIds.contains(Integer.valueOf(cryptoTokenInfo.getCryptoTokenId()));
                list.add(new CryptoTokenGuiInfo(cryptoTokenInfo, p11LibraryAlias, allowedActivation, allowedDeactivation, referenced));
                Collections.sort(list, new Comparator<CryptoTokenGuiInfo>() {
                    @Override
                    public int compare(CryptoTokenGuiInfo cryptoTokenInfo1, CryptoTokenGuiInfo cryptoTokenInfo2) {
                        return cryptoTokenInfo1.getTokenName().compareToIgnoreCase(cryptoTokenInfo2.getTokenName());
                    }
                });
            }
            cryptoTokenGuiInfos = list;
            cryptoTokenGuiList = new ListDataModel(cryptoTokenGuiInfos);
        }
        // If show the list, then we are on the main page and want to flush the two caches
        flushCurrent();
        setCurrentCryptoTokenEditMode(false);
        return cryptoTokenGuiList;
    }

    /** Invoked when admin requests a CryptoToken activation. */
    public void activateCryptoToken() throws AuthorizationDeniedException {
        if (cryptoTokenGuiList!=null) {
            final CryptoTokenGuiInfo current = (CryptoTokenGuiInfo) cryptoTokenGuiList.getRowData();
            try {
                cryptoTokenManagementSession.activate(authenticationToken, current.getCryptoTokenId(), current.getAuthenticationCode().toCharArray());
            } catch (CryptoTokenOfflineException e) {
                final String msg = "Activation of CryptoToken '" + current.getTokenName() + "' (" + current.getCryptoTokenId() +
                        ") by administrator " + authenticationToken.toString() + " failed. Device was unavailable.";
                super.addNonTranslatedErrorMessage(msg);
                log.info(msg);
            } catch (CryptoTokenAuthenticationFailedException e) {
                final String msg = "Activation of CryptoToken '" + current.getTokenName() + "' (" + current.getCryptoTokenId() +
                        ") by administrator " + authenticationToken.toString() + " failed. Authentication code was not correct.";
                super.addNonTranslatedErrorMessage(msg);
                log.info(msg);
            }
            flushCaches();
        }
    }

    /** Invoked when admin requests a CryptoToken deactivation. */
    public void deactivateCryptoToken() throws AuthorizationDeniedException {
        if (cryptoTokenGuiList!=null) {
            final CryptoTokenGuiInfo rowData = (CryptoTokenGuiInfo) cryptoTokenGuiList.getRowData();
            cryptoTokenManagementSession.deactivate(authenticationToken, rowData.getCryptoTokenId());
            flushCaches();
        }
    }
    
    /** Invoked when admin requests a CryptoToken deletion. */
    public void deleteCryptoToken() throws AuthorizationDeniedException {
        if (cryptoTokenGuiList!=null) {
            final CryptoTokenGuiInfo rowData = (CryptoTokenGuiInfo) cryptoTokenGuiList.getRowData();
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, rowData.getCryptoTokenId());
            flushCaches();
        }
    }
    
    /** @return true if admin may create new or modify existing CryptoTokens. */
    public boolean isAllowedToModify() {
        return accessControlSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource());
    }
    
    /** @return true if admin may delete CryptoTokens. */
    public boolean isAllowedToDelete() {
        return accessControlSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.DELETE_CRYPTOTOKEN.resource());
    }
    
    /** Invoked when admin requests a CryptoToken creation. */
    public void saveCurrentCryptoToken() throws AuthorizationDeniedException {
        String msg = null;
        if (!getCurrentCryptoToken().getSecret1().equals(getCurrentCryptoToken().getSecret2())) {
            msg = "Authentication codes do not match!";
        } else {
            try {
                final Properties properties = new Properties();
                String className = null;
                if (PKCS11CryptoToken.class.getSimpleName().equals(getCurrentCryptoToken().getType())) {
                    className = PKCS11CryptoToken.class.getName();
                    String library = getCurrentCryptoToken().getP11Library();
                    properties.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, library);
                    String slotTextValue = getCurrentCryptoToken().getP11Slot().trim();
                    String slotLabelType =   getCurrentCryptoToken().getP11SlotLabelType();
                    //Perform some name validation
                    if(slotLabelType.equals(Pkcs11SlotLabelType.SLOT_NUMBER.getKey())) {
                        if(!Pkcs11SlotLabelType.SLOT_NUMBER.validate(slotTextValue)) {
                            msg = "Slot must be an absolute number";
                        }
                    } else if(slotLabelType.equals(Pkcs11SlotLabelType.SLOT_INDEX.getKey())) {
                        if(slotTextValue.charAt(0) != 'i') {
                            slotTextValue = "i" + slotTextValue;
                        }
                        if(!Pkcs11SlotLabelType.SLOT_INDEX.validate(slotTextValue)) {
                            msg = "Slot must be an absolute number or use prefix 'i' for indexed slots.";
                        }                 
                    }
                 
                    // Verify that it is allowed
                    SlotList allowedSlots = getP11SlotList();
                    if (allowedSlots != null && !allowedSlots.contains(slotTextValue)) {
                        throw new IllegalArgumentException("Slot number "+slotTextValue+" is not allowed. Allowed slots are: "+allowedSlots);
                    }
                    
                    properties.setProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE, slotTextValue);
                    properties.setProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE, slotLabelType);
                    // The default should be null, but we will get a value "default" from the GUI code in this case..
                    final String p11AttributeFile = getCurrentCryptoToken().getP11AttributeFile();
                    if (!"default".equals(p11AttributeFile)) {
                        properties.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, p11AttributeFile);
                    }
                } else if (SoftCryptoToken.class.getSimpleName().equals(getCurrentCryptoToken().getType())) {
                    className = SoftCryptoToken.class.getName();
                    properties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
                }

                if (getCurrentCryptoToken().isAllowExportPrivateKey()) {
                    properties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, String.valueOf(getCurrentCryptoToken().isAllowExportPrivateKey()));
                }
                if (getCurrentCryptoToken().getKeyPlaceholders() != null) {
                    properties.setProperty(CryptoToken.KEYPLACEHOLDERS_PROPERTY, getCurrentCryptoToken().getKeyPlaceholders());
                }
                
                final char[] secret = getCurrentCryptoToken().getSecret1().toCharArray();
                final String name = getCurrentCryptoToken().getName();
                if (getCurrentCryptoTokenId() == 0) {
                    if (secret.length>0) {
                        if (getCurrentCryptoToken().isAutoActivate()) {
                            BaseCryptoToken.setAutoActivatePin(properties, new String(secret), true);
                        }
                        currentCryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, name, className, properties, null, secret);
                        msg = "CryptoToken created successfully.";
                    } else {
                        super.addNonTranslatedErrorMessage("You must provide an authentication code to create a CryptoToken.");
                    }
                } else {
                    if (getCurrentCryptoToken().isAutoActivate()) {
                        if (secret.length>0) {
                            BaseCryptoToken.setAutoActivatePin(properties, new String(secret), true);
                        } else {
                            // Indicate that we want to reuse current auto-pin if present
                            properties.put(CryptoTokenManagementSessionLocal.KEEP_AUTO_ACTIVATION_PIN, Boolean.TRUE.toString());
                        }
                    }
                    cryptoTokenManagementSession.saveCryptoToken(authenticationToken, getCurrentCryptoTokenId(), name, properties, secret);
                    msg = "CryptoToken saved successfully.";
                }
                flushCaches();
                setCurrentCryptoTokenEditMode(false);
            } catch (CryptoTokenOfflineException e) {
                msg = e.getMessage();
            } catch (CryptoTokenAuthenticationFailedException e) {
                msg = e.getMessage();
            } catch (AuthorizationDeniedException e) {
                msg = e.getMessage();
            } catch (IllegalArgumentException e) {
                msg = e.getMessage();
            } catch (Throwable e) {
                msg = e.getMessage();
                log.info("", e);
            }
        }
        if (msg != null) {
            if (log.isDebugEnabled()) {
                log.debug("Message displayed to user: " + msg);
            }
            super.addNonTranslatedErrorMessage(msg);
        }
    }

    /** Invoked when admin cancels a CryptoToken create or edit. */
    public void cancelCurrentCryptoToken() {
        setCurrentCryptoTokenEditMode(false);
        flushCaches();
    }
    
    public boolean isAnyP11LibraryAvailable() {
        return !getAvailableCryptoTokenP11Libraries().isEmpty();
    }
    
    /** @return a list of library SelectItems sort by display name for detected P11 libraries. */
    public List<SelectItem> getAvailableCryptoTokenP11Libraries() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for (Entry<String, WebConfiguration.P11LibraryInfo> entry : WebConfiguration.getAvailableP11LibraryToAliasMap().entrySet()) {
            ret.add(new SelectItem(entry.getKey(), entry.getValue().getAlias()));
        }
        // Sort by display name
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem s0, SelectItem s1) {
                return String.valueOf(s0.getValue()).compareTo(String.valueOf(s1));
            }
        });
        return ret;
    }

    /** @return alias if present otherwise the filename */
    private String getP11LibraryAlias(String library) {
        if (library == null) {
            return "";
        }
        
        WebConfiguration.P11LibraryInfo libinfo = WebConfiguration.getAvailableP11LibraryToAliasMap().get(library);
        if (libinfo == null) return library;
        String alias = libinfo.getAlias();
        if (alias == null || alias.isEmpty()) return library;
        return alias;
    }

    /** @return a list of library SelectItems sort by display name for detected P11 libraries. */
    public List<SelectItem> getAvailableCryptoTokenP11AttributeFiles() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ret.add(new SelectItem("default", "Default"));
        for (Entry<String, String> entry: WebConfiguration.getAvailableP11AttributeFiles().entrySet()) {
            ret.add(new SelectItem(entry.getKey(), entry.getValue()));
        }
        // Sort by display name
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem s0, SelectItem s1) {
                return String.valueOf(s0.getValue()).compareTo(String.valueOf(s1));
            }
        });
        return ret;
    }
    
    public List<SelectItem> getAvailableCryptoTokenP11SlotLabelTypes() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for (Pkcs11SlotLabelType type : Pkcs11SlotLabelType.values()) {
            if (type.equals(Pkcs11SlotLabelType.SUN_FILE)) {
                // jeklund doesn't believe that this is used anywhere, but he might be wrong
                continue;
            }
            final String display = EjbcaJSFHelper.getBean().getText().get(CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX + type.name());
            ret.add(new SelectItem(type.name(), display));
        }
        return ret;
    }

    /** Tries to retrieve the list of PKCS#11 slots (including token labels) using the Sun PKCS#11 Wrapper */
    public List<SelectItem> getAvailableCryptoTokenP11SlotTokenLabels() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        try {
            final File p11Library = new File(currentCryptoToken.getP11Library());
            SlotList allowedSlots = getP11SlotList();
            if (p11Library.exists()) {
                int index = 0;
                for (final String extendedTokenLabel : Pkcs11SlotLabel.getExtendedTokenLabels(p11Library)) {
                    // Returned list is in form "slotId;tokenLabel"
                    final String slotId = extendedTokenLabel.substring(0, extendedTokenLabel.indexOf(';'));
                    final String tokenLabel = extendedTokenLabel.substring(extendedTokenLabel.indexOf(';')+1);
                    if (!tokenLabel.isEmpty()) {
                        // Bravely assume that slots without a token label are not initialized or irrelevant
                        if (allowedSlots == null || allowedSlots.contains(slotId)) {
                            // Only show white-listed slots
                            ret.add(new SelectItem(tokenLabel, tokenLabel + " (index="+index + ", id="+slotId+")"));
                        }
                    }
                    index++;
                }
            }
        } catch (Exception e) {
            log.info("Administrator " + authenticationToken.toString() + " tries to list pkcs#11 slots using token label. Failed with: ", e);
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,
                    "Unable to retrieve token labels.", ""));
        }
        return ret;
    }

    /** @return alias if present otherwise the filename */
    public String getP11AttributeFileAlias(String p11AttributeFile) {
        if (p11AttributeFile == null || p11AttributeFile.length()==0) {
            return "Default";
        }
        String ret = WebConfiguration.getAvailableP11AttributeFiles().get(p11AttributeFile);
        if (ret == null || ret.length()==0) {
            ret = p11AttributeFile;
        }
        return ret;
    }

    /** @return a list of usable CryptoToken types */
    public List<SelectItem> getAvailableCryptoTokenTypes() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        final Collection<AvailableCryptoToken> availableCryptoTokens = CryptoTokenFactory.instance().getAvailableCryptoTokens();
        for (AvailableCryptoToken availableCryptoToken : availableCryptoTokens) {
            if (availableCryptoToken.getClassPath().equals(NullCryptoToken.class.getName())) {
                // Special case: Never expose the NullCryptoToken when creating new tokens
                continue;
            }
            if (availableCryptoToken.getClassPath().equals(PKCS11CryptoToken.class.getName())) {
                // Special case: Never expose the PKCS11CryptoToken when creating new tokens if no libraries are detected
                if (!isAnyP11LibraryAvailable()) {
                    if (log.isDebugEnabled()) {
                        log.debug("No known PKCS#11 libraries are available, not enabling PKCS#11 support in GUI. See web.properties for configuration of new PKCS#11 libraries.");
                    }
                    continue;
                }
            }
            // Use one the class's simpleName
            final String fullClassName = availableCryptoToken.getClassPath();
            ret.add(new SelectItem(fullClassName.substring(fullClassName.lastIndexOf('.')+1), availableCryptoToken.getName()));
        }
        return ret;
    }

    /** Used to draw the back link. No white-listing to the calling method must be careful to only use this for branching. */
    public String getParamRef() {
        final String reference = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("ref");
        if (reference==null || reference.isEmpty()) {
            return "default";
        }
        return reference;
    }
    
    /** @return the id of the CryptoToken that is subject to view or edit */
    public int getCurrentCryptoTokenId() {
        // Get the HTTP GET/POST parameter named "cryptoTokenId"
        final String cryptoTokenIdString = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("cryptoTokenId");        
        if (cryptoTokenIdString!=null && cryptoTokenIdString.length()>0) {
            try {
                int currentCryptoTokenId = Integer.parseInt(cryptoTokenIdString);
                // If there is a query parameter present and the id is different we flush the cache!
                if (currentCryptoTokenId != this.currentCryptoTokenId) {
                    flushCaches();
                    this.currentCryptoTokenId = currentCryptoTokenId;
                }
                // Always switch to edit mode for new ones and view mode for all others
                setCurrentCryptoTokenEditMode(currentCryptoTokenId == 0);
            } catch (NumberFormatException e) {
                log.info("Bad 'cryptoTokenId' parameter value.. set, but not a number..");
            }
        }
        return currentCryptoTokenId;
    }

    /** @return cached or populate a new CryptoToken GUI representation for view or edit */
    public CurrentCryptoTokenGuiInfo getCurrentCryptoToken() throws AuthorizationDeniedException {
        if (this.currentCryptoToken == null) {
            final int cryptoTokenId = getCurrentCryptoTokenId();
            final CurrentCryptoTokenGuiInfo currentCryptoToken = new CurrentCryptoTokenGuiInfo();
            // If the id is non-zero we try to load an existing token
            if (cryptoTokenId!=0) {
                final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
                if (cryptoTokenInfo == null) {
                    throw new RuntimeException("Could not load CryptoToken with cryptoTokenId " + cryptoTokenId);
                } else {
                    currentCryptoToken.setAllowExportPrivateKey(cryptoTokenInfo.isAllowExportPrivateKey());
                    currentCryptoToken.setAutoActivate(cryptoTokenInfo.isAutoActivation());
                    currentCryptoToken.setSecret1("");
                    currentCryptoToken.setSecret2("");
                    currentCryptoToken.setName(cryptoTokenInfo.getName());
                    currentCryptoToken.setType(cryptoTokenInfo.getType());
                    currentCryptoToken.setKeyPlaceholders(cryptoTokenInfo.getCryptoTokenProperties().getProperty(CryptoToken.KEYPLACEHOLDERS_PROPERTY, ""));
                    if (cryptoTokenInfo.getType().equals(PKCS11CryptoToken.class.getSimpleName())) {
                        currentCryptoToken.setP11AttributeFile(cryptoTokenInfo.getP11AttributeFile());
                        currentCryptoToken.setP11Library(cryptoTokenInfo.getP11Library());
                        currentCryptoToken.setP11Slot(cryptoTokenInfo.getP11Slot());
                        currentCryptoToken.setP11SlotLabelType(cryptoTokenInfo.getP11SlotLabelType());
                    }
                    currentCryptoToken.setActive(cryptoTokenInfo.isActive());
                    currentCryptoToken.setReferenced(getReferencedCryptoTokenIds().contains(Integer.valueOf(cryptoTokenId)));
                }
            }
            this.currentCryptoToken = currentCryptoToken;
        }
        return this.currentCryptoToken;
    }
    
    public void selectCryptoTokenType() {
        // NOOP: Only for page reload
    }
    public void selectCryptoTokenLabelType() {
        // Clear slot reference when we change type
        currentCryptoToken.setP11Slot("");
    }

    public boolean isCurrentCryptoTokenEditMode() { return currentCryptoTokenEditMode; }
    public void setCurrentCryptoTokenEditMode(boolean currentCryptoTokenEditMode) { this.currentCryptoTokenEditMode = currentCryptoTokenEditMode; }
    public void toggleCurrentCryptoTokenEditMode() { currentCryptoTokenEditMode ^= true; }
    
    //
    // KeyPair related stuff
    //
    
    // This default is taken from CAToken.SOFTPRIVATESIGNKEYALIAS, but we don't want to depend on the CA module
    private String newKeyPairAlias = "signKey";
    private String newKeyPairSpec = AlgorithmConstants.KEYALGORITHM_RSA+"4096";
    
    /** @return a List of available (but not necessarily supported by the underlying CryptoToken) key specs */
    public List<SelectItem> getAvailableKeySpecs() {
        final List<SelectItem> availableKeySpecs = new ArrayList<SelectItem>();
        final int[] SIZES_RSA = {1024, 1536, 2048, 3072, 4096, 6144, 8192};
        final int[] SIZES_DSA = {1024};
        for (int size : SIZES_RSA) {
            availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_RSA+size, AlgorithmConstants.KEYALGORITHM_RSA+" "+size));
        }
        for (int size : SIZES_DSA) {
            availableKeySpecs.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_DSA+size, AlgorithmConstants.KEYALGORITHM_DSA+" "+size));
        }
        try {
            final Map<String, List<String>> namedEcCurvesMap = AlgorithmTools.getNamedEcCurvesMap(PKCS11CryptoToken.class.getSimpleName().equals(getCurrentCryptoToken().getType()));
            final String[] keys = namedEcCurvesMap.keySet().toArray(new String[namedEcCurvesMap.size()]);
            Arrays.sort(keys);
            for (final String name : keys) {
                final StringBuilder names = new StringBuilder();
                for (final String alias : namedEcCurvesMap.get(name)) {
                    if (names.length()!=0) {
                        names.append(" / ");
                    }
                    names.append(alias);
                }
                availableKeySpecs.add(new SelectItem(name, AlgorithmConstants.KEYALGORITHM_ECDSA + " " + names.toString()));
            }
        } catch (AuthorizationDeniedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Ignoring exception " + e.getMessage());
            }
        }
        for (String alg : CesecoreConfiguration.getExtraAlgs()) {
            for (String subalg : CesecoreConfiguration.getExtraAlgSubAlgs(alg)) {
                final String title = CesecoreConfiguration.getExtraAlgSubAlgTitle(alg, subalg);
                final String name = CesecoreConfiguration.getExtraAlgSubAlgName(alg, subalg);
                availableKeySpecs.add(new SelectItem(name, title));
            }
        }
        return availableKeySpecs;
    }

    private String getEcKeySpecAliases(final String ecKeySpec) {
        StringBuilder ret = new StringBuilder();
        for (final String alias : AlgorithmTools.getEcKeySpecAliases(ecKeySpec)) {
            if (ret.length()!=0) {
                ret.append(" / ");
            }
            ret.append(alias);
        }
        return ret.toString();
    }

    /** @return true if admin may generate keys in the current CryptoTokens. */
    public boolean isAllowedToKeyGeneration() {
        return accessControlSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.GENERATE_KEYS.resource() + '/' + getCurrentCryptoTokenId());
    }

    /** @return true if admin may test keys from the current CryptoTokens. */
    public boolean isAllowedToKeyTest() {
        return accessControlSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.TEST_KEYS.resource() + '/' + getCurrentCryptoTokenId());
    }

    /** @return true if admin may remove keys from the current CryptoTokens. */
    public boolean isAllowedToKeyRemoval() {
        return accessControlSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.REMOVE_KEYS.resource() + '/' + getCurrentCryptoTokenId());
    }

    public boolean isKeyPairGuiListEmpty() throws AuthorizationDeniedException {
        return getKeyPairGuiList().getRowCount()==0;
    }
    
    public boolean isKeyPairGuiListFailed() throws AuthorizationDeniedException {
        getKeyPairGuiList(); // ensure loaded
        return keyPairGuiListError!=null;
    }
    
    public String getKeyPairGuiListError() throws AuthorizationDeniedException {
        getKeyPairGuiList(); // ensure loaded
        return keyPairGuiListError;
    }
    
    /** @return a list of all the keys in the current CryptoToken. */
    @SuppressWarnings({ "rawtypes", "unchecked" }) //JDK6 does not support typing for ListDataModel
    public ListDataModel getKeyPairGuiList() throws AuthorizationDeniedException {
        if (keyPairGuiList==null) {
            final List<KeyPairGuiInfo> ret = new ArrayList<KeyPairGuiInfo>();
            if (getCurrentCryptoToken().isActive()) {
                // Add existing key pairs
                try {
                    for (KeyPairInfo keyPairInfo : cryptoTokenManagementSession.getKeyPairInfos(getAdmin(), getCurrentCryptoTokenId())) {
                        ret.add(new KeyPairGuiInfo(keyPairInfo));
                    }
                } catch (CryptoTokenOfflineException ctoe) {
                    keyPairGuiListError = "Failed to load key pairs from CryptoToken: "+ctoe.getMessage();
                }
                // Add placeholders for key pairs
                String keyPlaceholders = getCurrentCryptoToken().getKeyPlaceholders();
                for (String template : keyPlaceholders.split("["+CryptoToken.KEYPLACEHOLDERS_OUTER_SEPARATOR+"]")) {
                    if (!template.trim().isEmpty()) {
                        ret.add(new KeyPairGuiInfo(template));
                    }
                }
            }
            Collections.sort(ret, new Comparator<KeyPairGuiInfo>() {
                @Override
                public int compare(KeyPairGuiInfo keyPairInfo1, KeyPairGuiInfo keyPairInfo2) {
                    return keyPairInfo1.getAlias().compareTo(keyPairInfo2.getAlias());
                }
            });
            keyPairGuiInfos = ret;
            keyPairGuiList = new ListDataModel(keyPairGuiInfos);
        }
        return keyPairGuiList;
    }

    public String getNewKeyPairSpec() { return newKeyPairSpec; }
    public void setNewKeyPairSpec(String newKeyPairSpec) { this.newKeyPairSpec = newKeyPairSpec; }

    public String getNewKeyPairAlias() { return newKeyPairAlias; }
    public void setNewKeyPairAlias(String newKeyPairAlias) { this.newKeyPairAlias = newKeyPairAlias; }

    /** Invoked when admin requests a new key pair generation. */
    public void generateNewKeyPair() {
        if (log.isTraceEnabled()) {
            log.trace(">generateNewKeyPair");
        }
        try {
            cryptoTokenManagementSession.createKeyPair(getAdmin(), getCurrentCryptoTokenId(), getNewKeyPairAlias(), getNewKeyPairSpec());
        } catch (CryptoTokenOfflineException e) {
            super.addNonTranslatedErrorMessage("Token is off-line. KeyPair cannot be generated.");
        } catch (Exception e) {
            super.addNonTranslatedErrorMessage(e.getMessage());
            final String logMsg = getAdmin().toString() + " failed to generate a keypair:";
            if (log.isDebugEnabled()) {
                log.debug(logMsg, e);
            } else {
                log.info(logMsg + e.getMessage());
            }
        }
        flushCaches();
        if (log.isTraceEnabled()) {
            log.trace("<generateNewKeyPair");
        }
    }
    
    /** Invoked when admin requests key pair generation from a template placeholder */
    public void generateFromTemplate() {
        if (log.isTraceEnabled()) {
            log.trace(">generateFromTemplate");
        }
        final KeyPairGuiInfo keyPairGuiInfo = (KeyPairGuiInfo) keyPairGuiList.getRowData();
        final String alias = keyPairGuiInfo.getAlias();
        final String keyspec = KeyTools.keyalgspecToKeyspec(keyPairGuiInfo.getKeyAlgorithm(), keyPairGuiInfo.getRawKeySpec());
        try {
            cryptoTokenManagementSession.createKeyPairFromTemplate(getAdmin(), getCurrentCryptoTokenId(), alias, keyspec);
        } catch (CryptoTokenOfflineException e) {
            super.addNonTranslatedErrorMessage("Token is off-line. KeyPair cannot be generated.");
        } catch (Exception e) {
            super.addNonTranslatedErrorMessage(e.getMessage());
            final String logMsg = getAdmin().toString() + " failed to generate a keypair:";
            if (log.isDebugEnabled()) {
                log.debug(logMsg, e);
            } else {
                log.info(logMsg + e.getMessage());
            }
        }
        flushCaches();
        if (log.isTraceEnabled()) {
            log.trace("<generateFromTemplate");
        }
    }
    
    /** Invoked when admin requests a test of a key pair. */
    public void testKeyPair() {
        final KeyPairGuiInfo keyPairGuiInfo = (KeyPairGuiInfo) keyPairGuiList.getRowData();
        final String alias = keyPairGuiInfo.getAlias();
        try {
            cryptoTokenManagementSession.testKeyPair(getAdmin(), getCurrentCryptoTokenId(), alias);
            super.addNonTranslatedInfoMessage(alias + " tested successfully.");
        } catch (Exception e) {
            super.addNonTranslatedErrorMessage(e.getMessage());
        }
    }
    
    /** Invoked when admin requests the removal of a key pair. */
    public void removeKeyPair() {
        final KeyPairGuiInfo keyPairGuiInfo = (KeyPairGuiInfo) keyPairGuiList.getRowData();
        final String alias = keyPairGuiInfo.getAlias();
        try {
            if (!keyPairGuiInfo.isPlaceholder()) {
                cryptoTokenManagementSession.removeKeyPair(getAdmin(), getCurrentCryptoTokenId(), alias);
            } else {
                cryptoTokenManagementSession.removeKeyPairPlaceholder(getAdmin(), getCurrentCryptoTokenId(), alias);
            }
            flushCaches();
        } catch (Exception e) {
            super.addNonTranslatedErrorMessage(e.getMessage());
        }
    }

    /** Invoked when admin requests the removal of multiple key pair. */
    public void removeSelectedKeyPairs() {
        if (keyPairGuiInfos!=null) {
            for (KeyPairGuiInfo cryptoTokenKeyPairInfo : keyPairGuiInfos) {
                if (cryptoTokenKeyPairInfo.isSelected()) {
                    try {
                        cryptoTokenManagementSession.removeKeyPair(getAdmin(), getCurrentCryptoTokenId(), cryptoTokenKeyPairInfo.getAlias());
                    } catch (Exception e) {
                        super.addNonTranslatedErrorMessage(e.getMessage());
                    }
                }
            }
        }
        flushCaches();
    }
    
    /** @return A SlotList that contains the allowed slots numbers and indexes, or null if there's no such restriction */
    private SlotList getP11SlotList() {
        String library = currentCryptoToken.getP11Library();
        if (library == null) return null;
        WebConfiguration.P11LibraryInfo libinfo = WebConfiguration.getAvailableP11LibraryToAliasMap().get(library);
        if (libinfo == null) return null;
        return libinfo.getSlotList();
    }
}
