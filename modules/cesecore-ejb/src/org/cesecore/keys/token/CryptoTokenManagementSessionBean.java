/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;

/**
 * @see CryptoTokenManagementSession
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CryptoTokenManagementSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CryptoTokenManagementSessionBean implements CryptoTokenManagementSessionLocal, CryptoTokenManagementSessionRemote {

    private static final Logger log = Logger.getLogger(CryptoTokenManagementSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
    private static final Random rnd = new SecureRandom();

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getCryptoTokenIds(final AuthenticationToken authenticationToken) {
        final List<Integer> allCryptoTokenIds = cryptoTokenSession.getCryptoTokenIds();
        final List<Integer> auhtorizedCryptoTokenIds = new ArrayList<Integer>();
        for (final Integer current : allCryptoTokenIds) {
            if (authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.VIEW.resource() + "/" + current.toString())) {
                auhtorizedCryptoTokenIds.add(current);
            }
        }
        return auhtorizedCryptoTokenIds;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CryptoToken getCryptoToken(final int cryptoTokenId) {
        return cryptoTokenSession.getCryptoToken(cryptoTokenId);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CryptoTokenInfo getCryptoTokenInfo(final AuthenticationToken authenticationToken, final int cryptoTokenId)
            throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, CryptoTokenRules.VIEW.resource() + "/" + cryptoTokenId)) {
            final String msg = INTRES.getLocalizedMessage("authorization.notauthorizedtoresource", CryptoTokenRules.VIEW.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return getCryptoTokenInfo(cryptoTokenId);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<CryptoTokenInfo> getCryptoTokenInfos(final AuthenticationToken authenticationToken) {
        final List<CryptoTokenInfo> cryptoTokenInfos = new ArrayList<CryptoTokenInfo>();
        for (final Integer cryptoTokenId : getCryptoTokenIds(authenticationToken)) {
            cryptoTokenInfos.add(getCryptoTokenInfo(cryptoTokenId));
        }
        return cryptoTokenInfos;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CryptoTokenInfo getCryptoTokenInfo(final int cryptoTokenId) {
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
        if (cryptoToken == null) {
            return null;
        }
        final boolean isActive = cryptoToken.getTokenStatus() == CryptoToken.STATUS_ACTIVE;
        final Properties cryptoTokenProperties = cryptoToken.getProperties();
        final boolean autoActivation = BaseCryptoToken.getAutoActivatePin(cryptoTokenProperties) != null;
        return new CryptoTokenInfo(cryptoTokenId, cryptoToken.getTokenName(), isActive, autoActivation, cryptoToken.getClass(), cryptoTokenProperties);
    }

    @Override
    public List<String> isCryptoTokenSlotUsed(final AuthenticationToken authenticationToken, final String tokenName,
            final String className, final Properties properties)
            throws AuthorizationDeniedException, CryptoTokenNameInUseException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, NoSuchSlotException {
        if (log.isTraceEnabled()) {
            log.trace(">isCryptoTokenUsed: " + tokenName + ", " + className);
        }
        if (CryptoTokenFactory.instance().getAvailableCryptoToken(className) == null) {
            throw new CryptoTokenClassNotFoundException("Invalid token class name: " + className);
        }
        // Creating a duplicate P11 crypto token can be destructive, ideally we would check all crypto tokens, 
        // but we only check the ones the admin has access to in order to not leak information 
        List<CryptoTokenInfo> infos = getCryptoTokenInfos(authenticationToken);
        List<String> providers = new ArrayList<>();
        String tokenP11Lib = properties.getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY);
        final String providerNameToCheck = createProviderName(tokenName, className, properties);
        if (log.isDebugEnabled()) {
            log.debug("isCryptoTokenUsed: Provider name to check for: "+providerNameToCheck);
        }
        // Return list of Crypto Token name
        List<String> ret = new ArrayList<>();
        // Only do this check for P11 tokens
        if (StringUtils.isNotEmpty(tokenP11Lib)) {
            for (CryptoTokenInfo cti : infos) {
                // We are concerned about PKCS#11 usage
                String ctiP11lib = cti.getP11Library();
                CryptoToken token = cryptoTokenSession.getCryptoToken(cti.getCryptoTokenId());
                final String ctiProviderName = token.getSignProviderName();
                providers.add(ctiProviderName);
                if (token != null) {
                    if (isP11SlotSame(tokenP11Lib, providerNameToCheck, ctiP11lib, ctiProviderName, cti.getName())) {
                        ret.add(ctiProviderName);
                    }
                }
            }
            // Check for database protection crypto tokens as well, these are not stored as crypto tokens in the database, but only 
            // as parameters in databaseprotection.properties, and thus requires special handling
            Provider[] installedProviders = Security.getProviders();
            if (installedProviders != null) {
                for (int i = 0; i < installedProviders.length; i++) {
                    final String installedProviderName = installedProviders[i].getName();
                    if (log.isDebugEnabled()) {
                        log.debug("isCryptoTokenUsed: Checking installed provider: "+installedProviderName);
                    }
                    if (StringUtils.equals(providerNameToCheck, installedProviderName)) {
                        // We found a match, but don't add duplicates
                        if (!providers.contains(installedProviderName)) {
                            log.debug("isCryptoTokenUsed: Found a match between "+providerNameToCheck+" and installed provider "+installedProviderName+", which was not already listed, must be a database protection token.");
                            ret.add(installedProviderName+" (database protection?)");
                        }
                    }
                }                
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<isCryptoTokenUsed: " + tokenName + ", " + className + ", " + ret.size());
        }
        return ret; 
    }

    private boolean isP11SlotSame(String tokenP11Lib, String providerNameToCheck, String ctiP11lib, String ctiProviderName, String ctiName) throws NoSuchSlotException {
        boolean ret = false;
        if (StringUtils.isNotEmpty(ctiP11lib)) {
            if (StringUtils.equalsIgnoreCase(tokenP11Lib, ctiP11lib)) {
                // We have a match on the library, watch out...check if we are using the same slot as well
                // Now it gets exciting, since you can address the slot through different things (slotID, slotName, p11Config)
                // it is really hard to check easily, we need to create the provider and see if the provider name is the same
                if (log.isDebugEnabled()) {
                    log.debug("isCryptoTokenUsed: Provider for token we check for: "+providerNameToCheck);
                    log.debug("isCryptoTokenUsed Provider for existing token: "+ctiProviderName);
                }
                if (StringUtils.equals(providerNameToCheck, ctiProviderName)) {
                    // We had a match, the caller knows the crypto token name
                    ret = true;
                }
            }
        }
        return ret;
    }

    private String createProviderName(final String tokenName, final String className, final Properties tokenprops) throws NoSuchSlotException {
        // Make a complete clone of the original properties, as we modify it to be non-addable-provider token properties below
        // if we did that on the original tokenprops, this method would have a side effect in modifying caller parameters 
        // (which causes things to break since the provider is not installed)
        Properties properties = new Properties();
        properties.putAll(tokenprops);
        properties.setProperty(PKCS11CryptoToken.DO_NOT_ADD_P11_PROVIDER, "true");                       
        final CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(className, properties, null, -1, tokenName, false);
        final String providerName = cryptoToken.getSignProviderName();
        if (log.isDebugEnabled()) {
            log.debug("isCryptoTokenUsed: Created provider (without installing) to check for collisions: "+providerName);
        }
        return providerName;
    }

    @Override
    public void createCryptoToken(final AuthenticationToken authenticationToken, final String tokenName, final Integer cryptoTokenId,
            final String className, final Properties properties, final byte[] data, final char[] authenticationCode)
            throws AuthorizationDeniedException, CryptoTokenNameInUseException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, NoSuchSlotException {
        if (log.isTraceEnabled()) {
            log.trace(">createCryptoToken: " + tokenName + ", " + className);
        }
        assertAuthorizedToModifyCryptoTokens(authenticationToken);
        if (CryptoTokenFactory.instance().getAvailableCryptoToken(className) == null) {
            throw new CryptoTokenClassNotFoundException("Invalid token class name: " + className);
        }

        // Note: if data is null, a new empty keystore will be created
        final CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(className, properties, data, cryptoTokenId.intValue(), tokenName, false);
        if (authenticationCode != null) {
            if (log.isDebugEnabled()) {
                log.debug("Activating new crypto token using supplied authentication code.");
            }
            cryptoToken.activate(authenticationCode);
        }

        // This property is used only once during crypto token creation
        properties.remove(CryptoToken.ALLOW_NONEXISTING_SLOT_PROPERTY);

        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", "Created CryptoToken with id " + cryptoTokenId);
        details.put("name", cryptoToken.getTokenName());
        details.put("encProviderName", cryptoToken.getEncProviderName());
        details.put("signProviderName", cryptoToken.getSignProviderName());
        putDelta(new Properties(), cryptoToken.getProperties(), details);
        cryptoTokenSession.mergeCryptoToken(cryptoToken);
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_CREATE, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<createCryptoToken: " + tokenName + ", " + className);
        }
    }

    @Override
    public int createCryptoToken(final AuthenticationToken authenticationToken, final String tokenName, final String className,
            final Properties properties, final byte[] data, final char[] authenticationCode) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, NoSuchSlotException,
            AuditRecordStorageException {
        final List<Integer> allCryptoTokenIds = cryptoTokenSession.getCryptoTokenIds();
        Integer cryptoTokenId = null;
        for (int i = 0; i < 100; i++) {
            final int current = Integer.valueOf(rnd.nextInt());
            if (!allCryptoTokenIds.contains(current)) {
                cryptoTokenId = current;
                break;
            }
        }
        if (cryptoTokenId == null) {
            throw new IllegalStateException("Failed to allocate a new cryptoTokenId.");
        }
        createCryptoToken(authenticationToken, tokenName, cryptoTokenId, className, properties, data, authenticationCode);
        return cryptoTokenId.intValue();
    }

    /**
     * Asserts if an authentication token is authorized to modify crypto tokens
     *
     * @param authenticationToken the authentication token to check
     * @throws AuthorizationDeniedException thrown if authorization was denied.
     */
    private void assertAuthorizedToModifyCryptoTokens(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource())) {
            final String msg = INTRES.getLocalizedMessage("authorization.notauthorizedtoresource", CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }

    @Override
    public void saveCryptoToken(AuthenticationToken authenticationToken, int cryptoTokenId, String tokenName, Properties properties,
            char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, NoSuchSlotException {
        if (log.isTraceEnabled()) {
            log.trace(">saveCryptoToken: " + tokenName + ", " + cryptoTokenId);
        }
        // Note that an admin that is authorized to modify a token could gain access to another HSM slot etc..
        if (!authorizationSession.isAuthorized(authenticationToken, CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource())) {
            final String msg = INTRES.getLocalizedMessage("authorization.notauthorizedtoresource", CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final CryptoToken currentCryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
        final String className = currentCryptoToken.getClass().getName();
        final byte[] tokendata = currentCryptoToken.getTokenData();
        // Handle presence of auto-activation indicators
        boolean keepAutoActivateIfPresent = Boolean.valueOf(String.valueOf(properties.get(CryptoTokenManagementSession.KEEP_AUTO_ACTIVATION_PIN)));
        properties.remove(CryptoTokenManagementSession.KEEP_AUTO_ACTIVATION_PIN);
        final String newPin = BaseCryptoToken.getAutoActivatePin(properties);
        if (newPin != null) {
            BaseCryptoToken.setAutoActivatePin(properties, newPin, true);
            authenticationCode = newPin.toCharArray();
        } else if (keepAutoActivateIfPresent) {
            final String currentPin = BaseCryptoToken.getAutoActivatePin(currentCryptoToken.getProperties());
            if (currentPin != null) {
                BaseCryptoToken.setAutoActivatePin(properties, currentPin, true);
                authenticationCode = null; // We have an auto-activation pin and it didn't change;
            }
        } else if (authenticationCode == null || authenticationCode.length == 0) {
            // Check if the token was auto-activated before. it is now manually activated, so use the auto-activation code one last time
            final String currentPin = BaseCryptoToken.getAutoActivatePin(currentCryptoToken.getProperties());
            if (currentPin != null) {
                authenticationCode = currentPin.toCharArray();
            }
        }
        // TODO: If the current token is active we would like to dig out the code used to activate it and activate the new one as well..
        // For SoftCryptoTokens, a new secret means that we should change it and it can only be done if the token is active
        CryptoToken newCryptoToken;
        try {
            newCryptoToken = CryptoTokenFactory.createCryptoToken(className, properties, tokendata, cryptoTokenId, tokenName);
            // If a new authenticationCode is provided we should verify it before we go ahead and merge
            if (authenticationCode != null && authenticationCode.length > 0) {
                newCryptoToken.deactivate();
                newCryptoToken.activate(authenticationCode);
            }
        } catch (CryptoTokenOfflineException e) {
            // If the crypto token can not be initialized, we have a problem and can not even disable auto-activation.
            // Go ahead and ignore this
            log.info("CryptoTokenOfflineException getting new crypto token for saving, ignoring this error and saving anyway: ", e);
            newCryptoToken = currentCryptoToken;
            newCryptoToken.setProperties(properties);
            newCryptoToken.setTokenName(tokenName);
        }
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", "Modified CryptoToken with id " + cryptoTokenId);
        putDelta("name", currentCryptoToken.getTokenName(), newCryptoToken.getTokenName(), details);
        putDelta("encProviderName", currentCryptoToken.getEncProviderName(), newCryptoToken.getEncProviderName(), details);
        putDelta("signProviderName", currentCryptoToken.getSignProviderName(), newCryptoToken.getSignProviderName(), details);
        putDelta(currentCryptoToken.getProperties(), newCryptoToken.getProperties(), details);
        cryptoTokenSession.mergeCryptoToken(newCryptoToken);
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_EDIT, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<saveCryptoToken: " + tokenName + ", " + cryptoTokenId);
        }
    }

    @Override
    public void saveCryptoToken(final AuthenticationToken authenticationToken, final int cryptoTokenId,
            final String newName, final String newPlaceholders) throws AuthorizationDeniedException, CryptoTokenNameInUseException {
        if (log.isTraceEnabled()) {
            log.trace(">saveCryptoToken: cryptoTokenId=" + cryptoTokenId + ", newName=" + newName);
        }
        if (!authorizationSession.isAuthorized(authenticationToken, CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource())) {
            final String msg = INTRES.getLocalizedMessage("authorization.notauthorizedtoresource", CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource(),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
        final String oldName = cryptoToken.getTokenName();
        cryptoToken.setTokenName(newName);
        final Properties properties = cryptoToken.getProperties();
        final String oldPlaceholders = cryptoToken.getProperties().getProperty(CryptoToken.KEYPLACEHOLDERS_PROPERTY);
        properties.setProperty(CryptoToken.KEYPLACEHOLDERS_PROPERTY, newPlaceholders);
        cryptoToken.setProperties(properties);

        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", "Modified name/placeholders of CryptoToken with id " + cryptoTokenId);
        putDelta("name", oldName, newName, details);
        putDelta("keyPlaceholders", oldPlaceholders, newPlaceholders, details);

        cryptoTokenSession.mergeCryptoToken(cryptoToken);
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_EDIT, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<saveCryptoToken: cryptoTokenId=" + cryptoTokenId + ", newName=" + newName);
        }
    }

    // Only removes reference
    @Override
    public void deleteCryptoToken(final AuthenticationToken authenticationToken, final int cryptoTokenId) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, CryptoTokenRules.DELETE_CRYPTOTOKEN.resource() + "/" + cryptoTokenId)) {
            throw new AuthorizationDeniedException();
        }
        if (cryptoTokenSession.removeCryptoToken(cryptoTokenId)) {
            securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_DELETION, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                    authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, "Deleted CryptoToken with id " + cryptoTokenId);
        } else if (log.isDebugEnabled()) {
            log.debug("Crypto token with id " + cryptoTokenId + " does not exist and can not be deleted.");
        }
    }

    @Override
    public boolean isCryptoTokenStatusActive(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException {
        assertAuthorizationNoLog(authenticationToken, cryptoTokenId, CryptoTokenRules.VIEW.resource() + "/" + cryptoTokenId);
        return isCryptoTokenStatusActive(cryptoTokenId);
    }

    @Override
    public boolean isCryptoTokenStatusActive(int cryptoTokenId) {
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
        if (cryptoToken == null) {
            return false;
        }
        return cryptoToken.getTokenStatus() == CryptoToken.STATUS_ACTIVE;
    }
    
    @Override
    public boolean isCryptoTokenPresent(final AuthenticationToken authenticationToken, final int cryptoTokenId) throws AuthorizationDeniedException {
        assertAuthorizationNoLog(authenticationToken, cryptoTokenId, CryptoTokenRules.VIEW.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
        return cryptoToken != null;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void activate(final AuthenticationToken authenticationToken, final int cryptoTokenId, final char[] authenticationCode)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        assertAuthorization(authenticationToken, cryptoTokenId, CryptoTokenRules.ACTIVATE.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);
        cryptoToken.activate(authenticationCode);
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_ACTIVATION, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, "Activated CryptoToken '" + cryptoToken.getTokenName()
                        + "' with id " + cryptoTokenId);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void deactivate(final AuthenticationToken authenticationToken, final int cryptoTokenId) throws AuthorizationDeniedException {
        assertAuthorization(authenticationToken, cryptoTokenId, CryptoTokenRules.DEACTIVATE.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);
        cryptoToken.deactivate();
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_DEACTIVATION, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null,
                "Deactivated CryptoToken '" + cryptoToken.getTokenName() + "' with id " + cryptoTokenId);
        if (cryptoToken.isAutoActivationPinPresent()) {
            securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_REACTIVATION, EventStatus.VOID, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                    authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, "Reactivated CryptoToken '" + cryptoToken.getTokenName()
                            + "' with id " + cryptoTokenId);
        }

    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean updatePin(AuthenticationToken authenticationToken, Integer cryptoTokenId, char[] currentAuthenticationCode,
            char[] newAuthenticationCode, boolean updateOnly) throws AuthorizationDeniedException, CryptoTokenAuthenticationFailedException,
            CryptoTokenOfflineException {
        final String[] requiredAuthorization = new String[] { CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource() + "/" + cryptoTokenId,
                CryptoTokenRules.ACTIVATE.resource() + "/" + cryptoTokenId, CryptoTokenRules.DEACTIVATE.resource() + "/" + cryptoTokenId };
        if (!authorizationSession.isAuthorized(authenticationToken, requiredAuthorization)) {
            final String msg = INTRES.getLocalizedMessage("authorization.notauthorizedtoresource", Arrays.toString(requiredAuthorization),
                    authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        CryptoToken cryptoToken = getCryptoToken(cryptoTokenId);
        final Properties cryptoTokenProperties = cryptoToken.getProperties();
        // Get current auto-activation pin (if any)
        final String oldAutoActivationPin = BaseCryptoToken.getAutoActivatePin(cryptoTokenProperties);
        if (oldAutoActivationPin == null && (updateOnly || newAuthenticationCode == null)) {
            // This is a NOOP call that will not lead to any change
            return false;
        }
        if (SoftCryptoToken.class.getName().equals(cryptoToken.getClass().getName())) {
            CryptoProviderTools.installBCProviderIfNotAvailable();
            final KeyStore keystore;
            try {
                keystore = KeyStore.getInstance("PKCS12", "BC");
                keystore.load(new ByteArrayInputStream(cryptoToken.getTokenData()), currentAuthenticationCode);
            } catch (Exception e) {
                final String msg = "Failed to use supplied current PIN." + " " + e;
                log.info(msg);
                throw new CryptoTokenAuthenticationFailedException(msg);
            }
            if (newAuthenticationCode == null) {
                // When no new pin is supplied, we will not modify the key-store and just remove the current auto-activation pin
                cryptoTokenProperties.remove(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
                // We'll also remove the default password option
                cryptoTokenProperties.put(SoftCryptoToken.NODEFAULTPWD, Boolean.TRUE.toString());
                cryptoToken.setProperties(cryptoTokenProperties);
            } else {
                try {
                    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    keystore.store(baos, newAuthenticationCode);
                    baos.close();
                    if (oldAutoActivationPin != null || !updateOnly) {
                        BaseCryptoToken.setAutoActivatePin(cryptoTokenProperties, new String(newAuthenticationCode), true);
                    } else {
                        log.debug("Auto-activation will not be used. Only changing pin for soft CryptoToken keystore.");
                    }
                    cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), cryptoTokenProperties, baos.toByteArray(),
                            cryptoTokenId, cryptoToken.getTokenName());
                } catch (Exception e) {
                    log.info("Unable to store soft keystore with new PIN: " + e);
                    throw new CryptoTokenAuthenticationFailedException("Unable to store soft keystore with new PIN");
                }
            }
        } else {
            if (oldAutoActivationPin != null) {
                // If we have an old auto-activation pin we will compare the "current" with this value to avoid deactivating the token
                if (!oldAutoActivationPin.equals(new String(currentAuthenticationCode))) {
                    final String msg = "Supplied PIN did not match auto-activation PIN.";
                    log.info(msg);
                    throw new CryptoTokenAuthenticationFailedException(msg);
                } else {
                    log.debug("Successfully verified the PIN for non-soft CryptoToken by comparing supplied PIN to auto-activation PIN.");
                }
            } else {
                // If we don't have an auto-activation pin to compare the supplied PIN to, we need to verify the supplied
                // PIN can be used in a de-activation/activation cycle.
                final boolean wasInactive = !isCryptoTokenStatusActive(authenticationToken, cryptoTokenId);
                cryptoToken.deactivate();
                cryptoToken.activate(currentAuthenticationCode);
                if (wasInactive) {
                    // Note that there is a small glitch here where the token was active, but we have no other options to verify the pin
                    cryptoToken.deactivate();
                }
            }
            if (newAuthenticationCode == null) {
                cryptoTokenProperties.remove(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
            } else {
                BaseCryptoToken.setAutoActivatePin(cryptoTokenProperties, new String(newAuthenticationCode), true);
            }
            cryptoToken.setProperties(cryptoTokenProperties);
        }
        // Save the modified CryptoToken
        try {
            cryptoTokenSession.mergeCryptoToken(cryptoToken);
        } catch (CryptoTokenNameInUseException e) {
            // This should not happen here since we use the same name and id
            throw new RuntimeException(e);
        }
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_UPDATEPIN, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null,
                "Updated PIN of CryptoToken '" + cryptoToken.getTokenName() + "' with id " + cryptoTokenId);
        // Return the current auto-activation state
        return BaseCryptoToken.getAutoActivatePin(cryptoTokenProperties) != null;
    }

    @Override
    public List<KeyPairInfo> getKeyPairInfos(final AuthenticationToken authenticationToken, final int cryptoTokenId)
            throws CryptoTokenOfflineException, AuthorizationDeniedException {
        assertAuthorizationNoLog(authenticationToken, cryptoTokenId, CryptoTokenRules.VIEW.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);
        final List<KeyPairInfo> ret = new ArrayList<KeyPairInfo>();
        for (final String alias : getKeyPairAliasesInternal(cryptoToken)) {
            final PublicKey publicKey = cryptoToken.getPublicKey(alias);
            final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(publicKey);
            final String keySpecification = AlgorithmTools.getKeySpecification(publicKey);
            final String subjectKeyId = new String(Hex.encode(KeyTools.createSubjectKeyId(publicKey).getKeyIdentifier()));
            ret.add(new KeyPairInfo(alias, keyAlgorithm, keySpecification, subjectKeyId));
        }
        return ret;
    }

    @Override
    public KeyPairInfo getKeyPairInfo(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws CryptoTokenOfflineException,
            AuthorizationDeniedException {
        assertAuthorizationNoLog(authenticationToken, cryptoTokenId, CryptoTokenRules.VIEW.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);
        if (!getKeyPairAliasesInternal(cryptoToken).contains(alias)) {
            return null;
        }
        final PublicKey publicKey = cryptoToken.getPublicKey(alias);
        final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(publicKey);
        final String keySpecification = AlgorithmTools.getKeySpecification(publicKey);
        final String subjectKeyId = new String(Hex.encode(KeyTools.createSubjectKeyId(publicKey).getKeyIdentifier()));
        return new KeyPairInfo(alias, keyAlgorithm, keySpecification, subjectKeyId);
    }

    @Override
    public PublicKeyWrapper getPublicKey(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException,
            CryptoTokenOfflineException {
        assertAuthorizationNoLog(authenticationToken, cryptoTokenId, CryptoTokenRules.VIEW.resource() + "/" + cryptoTokenId);
        return new PublicKeyWrapper(getCryptoTokenAndAssertExistence(cryptoTokenId).getPublicKey(alias));
    }

    @Override
    public Integer getIdFromName(final String cryptoTokenName) {
        if (cryptoTokenName == null) {
            return null;
        }
        final Map<String, Integer> cachedNameToIdMap = cryptoTokenSession.getCachedNameToIdMap();
        Integer cryptoTokenId = cachedNameToIdMap.get(cryptoTokenName);
        if (cryptoTokenId == null) {
            // Ok.. so it's not in the cache.. look for it the hard way..
            for (final Integer currentCryptoTokenId : cryptoTokenSession.getCryptoTokenIds()) {
                // Don't lookup CryptoTokens we already have in the id to name cache
                if (!cachedNameToIdMap.values().contains(currentCryptoTokenId)) {
                    final CryptoToken currentCryptoToken = cryptoTokenSession.getCryptoToken(currentCryptoTokenId.intValue());
                    final String currentCryptoTokenName = currentCryptoToken == null ? null : currentCryptoToken.getTokenName();
                    if (cryptoTokenName.equals(currentCryptoTokenName)) {
                        cryptoTokenId = currentCryptoTokenId;
                        break;
                    }
                }
            }
        }
        return cryptoTokenId;
    }

    @Override
    public List<String> getKeyPairAliases(final AuthenticationToken authenticationToken, final int cryptoTokenId)
            throws AuthorizationDeniedException, CryptoTokenOfflineException {
        assertAuthorizationNoLog(authenticationToken, cryptoTokenId, CryptoTokenRules.VIEW.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);
        return getKeyPairAliasesInternal(cryptoToken);
    }

    private List<String> getKeyPairAliasesInternal(final CryptoToken cryptoToken) throws CryptoTokenOfflineException {
        try {
            final List<String> aliasEnumeration = cryptoToken.getAliases();
            final List<String> keyPairAliases = new ArrayList<String>();
            for(final String currentAlias : aliasEnumeration) {
                try {
                    if (cryptoToken.getPublicKey(currentAlias) != null && cryptoToken.getPrivateKey(currentAlias) != null) {
                        // A key pair exists for this alias, so add it
                        keyPairAliases.add(currentAlias);
                    }
                } catch (CryptoTokenOfflineException ignored) {
                    if (log.isDebugEnabled()) {
                        log.debug("Ignord key alias '"+currentAlias+"' in crypto token '"+cryptoToken.getTokenName()+"' since it is missing a public and/or private key. Perhaps it is a symmetric key?");
                    }
                }
            }
            return keyPairAliases;
        } catch (KeyStoreException e) {
            throw new CryptoTokenOfflineException(e);
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void createKeyPair(final AuthenticationToken authenticationToken, final int cryptoTokenId, final String alias,
            final String keySpecificationParam) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        assertAuthorization(authenticationToken, cryptoTokenId, CryptoTokenRules.GENERATE_KEYS.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);
        // Check if alias is already in use
        assertAliasNotInUse(cryptoToken, alias);

        // Support "RSAnnnn" and convert it to the legacy format "nnnn"
        final String keySpecification;
        if (keySpecificationParam.startsWith(AlgorithmConstants.KEYALGORITHM_RSA)) {
            keySpecification = keySpecificationParam.substring(AlgorithmConstants.KEYALGORITHM_RSA.length());
        } else {
            keySpecification = keySpecificationParam;
        }
        // Check if keySpec is valid
        KeyTools.checkValidKeyLength(keySpecification);
        // Audit log before generation. If the token is an HSM the merge will not make a difference.
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", "Generated new keypair in CryptoToken " + cryptoTokenId);
        details.put("keyAlias", alias);
        details.put("keySpecification", keySpecification);
        cryptoToken.generateKeyPair(keySpecification, alias);
        cryptoToken.testKeyPair(alias);
        // Merge is important for soft tokens where the data is persisted in the database, but will also update lastUpdate
        try {
            cryptoTokenSession.mergeCryptoToken(cryptoToken);
        } catch (CryptoTokenNameInUseException e) {
            throw new RuntimeException(e); // We have not changed the name of the CrytpoToken here, so this should never happen
        }
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_GEN_KEYPAIR, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, details);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void createKeyPairWithSameKeySpec(final AuthenticationToken authenticationToken, final int cryptoTokenId, final String currentAlias,
            final String newAlias) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        assertAuthorization(authenticationToken, cryptoTokenId, CryptoTokenRules.GENERATE_KEYS.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);
        assertAliasNotInUse(cryptoToken, newAlias);
        final PublicKey publicKey = cryptoToken.getPublicKey(currentAlias);
        final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(publicKey);
        final String keySpecification;
        if (AlgorithmConstants.KEYALGORITHM_DSA.equals(keyAlgorithm)) {
            keySpecification = AlgorithmConstants.KEYALGORITHM_DSA + AlgorithmTools.getKeySpecification(publicKey);
        } else {
            keySpecification = AlgorithmTools.getKeySpecification(publicKey);
        }
        KeyTools.checkValidKeyLength(keySpecification);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", "Generated new keypair in CryptoToken " + cryptoTokenId);
        details.put("keyAlias", newAlias);
        details.put("keySpecification", keySpecification);
        cryptoToken.generateKeyPair(keySpecification, newAlias);
        cryptoToken.testKeyPair(newAlias);
        try {
            cryptoTokenSession.mergeCryptoToken(cryptoToken);
        } catch (CryptoTokenNameInUseException e) {
            throw new RuntimeException(e); // We have not changed the name of the CrytpoToken here, so this should never happen
        }
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_GEN_KEYPAIR, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, details);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void createKeyPairFromTemplate(AuthenticationToken authenticationToken, int cryptoTokenId, String alias, String keySpecification)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException {
        createKeyPair(authenticationToken, cryptoTokenId, alias, keySpecification);
        removeKeyPairPlaceholder(authenticationToken, cryptoTokenId, alias);
    }

    @Override
    public boolean isAliasUsedInCryptoToken(final int cryptoTokenId, final String alias) {
        return getCryptoToken(cryptoTokenId).isAliasUsed(alias);
    }

    /** @throws InvalidKeyException if the alias is in use by a private, public or symmetric key */
    private void assertAliasNotInUse(final CryptoToken cryptoToken, final String alias) throws InvalidKeyException {
        if (cryptoToken.isAliasUsed(alias)) {
            throw new InvalidKeyException("alias " + alias + " is in use");
        }
    }

    @Override
    public void removeKeyPair(final AuthenticationToken authenticationToken, final int cryptoTokenId, final String alias)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException {
        assertAuthorization(authenticationToken, cryptoTokenId, CryptoTokenRules.REMOVE_KEYS.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);
        // Check if alias is in use
        if (!cryptoToken.isAliasUsed(alias)) {
            throw new InvalidKeyException("Alias " + alias + " is not in use");
        }
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", "Deleted key pair from CryptoToken " + cryptoTokenId);
        details.put("keyAlias", alias);
        try {
            cryptoToken.deleteEntry(alias);
        } catch (KeyStoreException e) {
            throw new InvalidKeyException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException(e);
        } catch (CertificateException e) {
            throw new InvalidKeyException(e);
        } catch (IOException e) {
            throw new InvalidKeyException(e);
        }
        assertAliasNotInUse(cryptoToken, alias);
        log.debug("cryptoTokenSession.mergeCryptoToken");
        // Merge is important for soft tokens where the data is persisted in the database, but will also update lastUpdate
        try {
            cryptoTokenSession.mergeCryptoToken(cryptoToken);
        } catch (CryptoTokenNameInUseException e) {
            throw new IllegalStateException(e); // We have not changed the name of the CrytpoToken here, so this should never happen
        }
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_DELETE_ENTRY, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, details);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void removeKeyPairPlaceholder(final AuthenticationToken authenticationToken, final int cryptoTokenId, final String alias)
            throws AuthorizationDeniedException, InvalidKeyException {
        assertAuthorization(authenticationToken, cryptoTokenId, CryptoTokenRules.REMOVE_KEYS.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);

        boolean removed = false;
        final Properties props = new Properties();
        props.putAll(cryptoToken.getProperties());
        final String placeholdersString = props.getProperty(CryptoToken.KEYPLACEHOLDERS_PROPERTY, "");
        final List<String> entries = new ArrayList<String>(Arrays.asList(placeholdersString.split("["+CryptoToken.KEYPLACEHOLDERS_OUTER_SEPARATOR+"]")));
        final Iterator<String> iter = entries.iterator();
        while (iter.hasNext()) {
            final String entry = iter.next();
            if (entry.startsWith(alias + CryptoToken.KEYPLACEHOLDERS_INNER_SEPARATOR)) {
                iter.remove();
                removed = true;
            }
        }

        if (removed) {
            final String newValue = StringUtils.join(entries, CryptoToken.KEYPLACEHOLDERS_OUTER_SEPARATOR);
            props.setProperty(CryptoToken.KEYPLACEHOLDERS_PROPERTY, newValue);
            cryptoToken.setProperties(props);
        }

        // Check if alias is in use
        if (!removed) {
            throw new InvalidKeyException("Alias " + alias + " is not in use");
        }

        try {
            cryptoTokenSession.mergeCryptoToken(cryptoToken);
        } catch (CryptoTokenNameInUseException e) {
            throw new IllegalStateException(e); // We have not changed the name of the CrytpoToken here, so this should never happen
        }

        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", "Deleted key pair placeholder from CryptoToken " + cryptoTokenId);
        details.put("keyAlias", alias);
        securityEventsLoggerSession.log(EventTypes.CRYPTOTOKEN_DELETE_ENTRY, EventStatus.SUCCESS, ModuleTypes.CRYPTOTOKEN, ServiceTypes.CORE,
                authenticationToken.toString(), String.valueOf(cryptoTokenId), null, null, details);
    }

    @Override
    public void testKeyPair(final AuthenticationToken authenticationToken, final int cryptoTokenId, final String alias)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException {
        assertAuthorization(authenticationToken, cryptoTokenId, CryptoTokenRules.TEST_KEYS.resource() + "/" + cryptoTokenId);
        final CryptoToken cryptoToken = getCryptoTokenAndAssertExistence(cryptoTokenId);
        cryptoToken.testKeyPair(alias);
    }

    private void assertAuthorization(final AuthenticationToken authenticationToken, final int cryptoTokenId, final String resource)
            throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, resource)) {
            final String msg = INTRES.getLocalizedMessage("authorization.notauthorizedtoresource", resource, authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }
    
    private void assertAuthorizationNoLog(final AuthenticationToken authenticationToken, final int cryptoTokenId, final String resource)
            throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, resource)) {
            final String msg = INTRES.getLocalizedMessage("authorization.notauthorizedtoresource", resource, authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }

    /** @return a CryptoToken for the requested Id if exists. Never returns null. */
    private CryptoToken getCryptoTokenAndAssertExistence(int cryptoTokenId) {
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
        if (cryptoToken == null) {
            throw new RuntimeException("No such CryptoToken for id " + cryptoTokenId);
        }
        return cryptoToken;
    }

    /** Helper method for audit logging changes */
    private void putDelta(Properties oldProperties, Properties newProperties, Map<String, Object> details) {
        // Find out what has happended to all the old properties
        for (final Object key : oldProperties.keySet()) {
            final String oldValue = oldProperties.getProperty(String.valueOf(key));
            final String newValue = newProperties.getProperty(String.valueOf(key));
            putDelta(String.valueOf(key), oldValue, newValue, details);
        }
        // Find out which new properties that did not exist in the old
        for (final Object key : newProperties.keySet()) {
            final String oldValue = oldProperties.getProperty(String.valueOf(key));
            if (oldValue == null) {
                final String newValue = newProperties.getProperty(String.valueOf(key));
                putDelta(String.valueOf(key), oldValue, newValue, details);
            }
        }
    }

    /** Helper method for audit logging changes */
    private void putDelta(String key, String oldValue, String newValue, Map<String, Object> details) {
        // Treat the auto-activation pin with care
        if (BaseCryptoToken.AUTOACTIVATE_PIN_PROPERTY.equals(key)) {
            if (oldValue == null && newValue == null) {
                // NOP
            } else if (oldValue == null && newValue != null) {
                details.put("autoActivation", "added");
                details.put("autoActivationPinProtection", StringTools.getEncryptVersionFromString(newValue));
            } else if (oldValue != null && newValue == null) {
                details.put("autoActivation", "removed");
            } else if (!oldValue.equals(newValue)) {
                details.put("autoActivation", "pin changed");
                details.put("autoActivationPinProtection", StringTools.getEncryptVersionFromString(newValue));
            }
        } else {
            if (oldValue == null && newValue == null) {
                // NOP
            } else if (oldValue == null && newValue != null) {
                details.put("added:" + key, newValue);
            } else if (oldValue != null && newValue == null) {
                details.put("removed:" + key, oldValue);
            } else if (!oldValue.equals(newValue)) {
                details.put("changed:" + key, newValue);
            } else {
                details.put(key, newValue);
            }
        }
    }
}
