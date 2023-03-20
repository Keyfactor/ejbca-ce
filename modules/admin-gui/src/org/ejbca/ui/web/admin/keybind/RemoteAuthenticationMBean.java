/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.keybind;

import java.io.Serializable;
import java.security.KeyStoreException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.enterprise.context.SessionScoped;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Named;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 *
 */
@Named("remoteAuthenticationMBean")
@SessionScoped
public class RemoteAuthenticationMBean extends InternalKeyBindingMBeanBase {

    private static final long serialVersionUID = 1L;

    private static final String REMOTE_AUTHENTICATION = "AuthenticationKeyBinding";

    private final AuthenticationToken authenticationToken = getAdmin();
   
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private InternalKeyBindingMgmtSessionLocal internalKeyBindingSession;
    
    @Override
    public String getSelectedInternalKeyBindingType() {
        return REMOTE_AUTHENTICATION;
    }
    
    @Override
    protected String getKeybindingTypeName() {
        return "Remote Authenticator";
    }
    
    /** Invoked when the user is done configuring a new InternalKeyBinding and wants to persist it */
    @SuppressWarnings("unchecked")
    @Override
    public void createNew() {
        if (getCurrentCryptoToken() == null) {
            // Should not happen
            FacesContext.getCurrentInstance().addMessage(
                    null,
                    new FacesMessage(FacesMessage.SEVERITY_ERROR, "No Crypto Token exists when trying to create a new Key Binding with name "
                            + getCurrentName(), null));
        } else {
            //Make sure that the crypto token actually has keys
            CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(getCurrentCryptoToken());
            try {
                if(cryptoToken.getAliases().isEmpty()) {
                    // Should not happen
                    FacesContext.getCurrentInstance().addMessage(
                            null,
                            new FacesMessage(FacesMessage.SEVERITY_ERROR, "Selected crypto token contains no keys", null));
                    return;
                }
            } catch (KeyStoreException e) {
                FacesContext.getCurrentInstance().addMessage(
                        null,
                        new FacesMessage(FacesMessage.SEVERITY_ERROR, "Selected crypto token has not been initialized.", null));
                return;
            } catch (CryptoTokenOfflineException e1) {
                FacesContext.getCurrentInstance().addMessage(
                        null,
                        new FacesMessage(FacesMessage.SEVERITY_ERROR, "Selected crypto token is offline.", null));
                return;
            }
            
            
            try {
                final Map<String, Serializable> dataMap = new HashMap<>();
                final List<DynamicUiProperty<? extends Serializable>> internalKeyBindingProperties = (List<DynamicUiProperty<? extends Serializable>>) getInternalKeyBindingPropertyList()
                        .getWrappedData();
                for (final DynamicUiProperty<? extends Serializable> property : internalKeyBindingProperties) {
                    dataMap.put(property.getName(), property.getValue());
                }
                setCurrentInternalKeybindingId(String.valueOf(internalKeyBindingSession.createInternalKeyBinding(authenticationToken,
                        getSelectedInternalKeyBindingType(), getCurrentName(), InternalKeyBindingStatus.DISABLED, null,
                        getCurrentCryptoToken().intValue(), getCurrentKeyPairAlias(), getCurrentSignatureAlgorithm(), dataMap,
                        (List<InternalKeyBindingTrustEntry>) getTrustedCertificates().getWrappedData())));

                FacesContext.getCurrentInstance().addMessage(null,
                        new FacesMessage(getCurrentName() + " created with ID " + getCurrentInternalKeyBindingId()));
                setInEditMode(false);
            } catch (AuthorizationDeniedException | InternalKeyBindingNameInUseException | CryptoTokenOfflineException | InvalidAlgorithmException 
                    | InternalKeyBindingNonceConflictException e) {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
            }
        }
    }
    
    @SuppressWarnings("unchecked")
    public void saveCurrent() throws InternalKeyBindingNonceConflictException {
        try {
            final InternalKeyBinding internalKeyBinding = internalKeyBindingSession.getInternalKeyBinding(authenticationToken,
                    Integer.parseInt(getCurrentInternalKeyBindingId()));
            internalKeyBinding.setName(getCurrentName());
            if (isCryptoTokenActive()) {
                final int loadedCryptoTokenId = internalKeyBinding.getCryptoTokenId();
                final String loadedKeyPairAlias = internalKeyBinding.getKeyPairAlias();
                if (loadedCryptoTokenId != getCurrentCryptoToken().intValue() || !loadedKeyPairAlias.equals(getCurrentKeyPairAlias())) {
                    // Since we have changed the referenced key, the referenced certificate (if any) is no longer valid
                    internalKeyBinding.setCertificateId(null);
                }
                internalKeyBinding.setCryptoTokenId(getCurrentCryptoToken().intValue());
                internalKeyBinding.setKeyPairAlias(getCurrentKeyPairAlias());
                internalKeyBinding.setSignatureAlgorithm(getCurrentSignatureAlgorithm());
                if (getCurrentKeyPairAlias() == null || getCurrentKeyPairAlias().length() == 0) {
                    internalKeyBinding.setNextKeyPairAlias(null);
                } else {
                    internalKeyBinding.setNextKeyPairAlias(getCurrentKeyPairAlias());
                }
            }
            internalKeyBinding.setTrustedCertificateReferences((List<InternalKeyBindingTrustEntry>) getTrustedCertificates().getWrappedData());
            final List<DynamicUiProperty<? extends Serializable>> internalKeyBindingProperties =
                    (List<DynamicUiProperty<? extends Serializable>>) getInternalKeyBindingPropertyList().getWrappedData();
            for (final DynamicUiProperty<? extends Serializable> property : internalKeyBindingProperties) {
                internalKeyBinding.setProperty(property.getName(), property.getValue());
            }

            setCurrentInternalKeybindingId(
                    String.valueOf(internalKeyBindingSession.persistInternalKeyBinding(authenticationToken, internalKeyBinding)));
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(getCurrentName() + " saved"));
        } catch (AuthorizationDeniedException | InternalKeyBindingNameInUseException | IllegalArgumentException e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
        }
    }
    
}
