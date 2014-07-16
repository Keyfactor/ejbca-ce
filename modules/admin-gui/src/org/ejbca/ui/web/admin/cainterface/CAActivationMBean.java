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
package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.NullCryptoToken;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * JSF Managed Bean or the CA Activation page of the Admin GUI.
 *
 * @version $Id$
 */
public class CAActivationMBean extends BaseManagedBean implements Serializable {

	private static final Logger log = Logger.getLogger(CAActivationMBean.class);

	private static final long serialVersionUID = -2660384552215596717L;
	
	/** GUI representation of a CA for the activation view */
	public class CaActivationGuiInfo {
	    private final int status;
	    private final String name;
	    private final int caId;
        private boolean monitored;
        private boolean monitoredNewState;
        private boolean newState;
	    
	    private CaActivationGuiInfo(int status, boolean monitored, String name, int caId) {
	        this.status = status;
            this.newState = isActive();
	        this.monitored = monitored;
	        this.monitoredNewState = monitored;
	        this.name = name;
	        this.caId = caId;
	    }

        public boolean isActive() { return status == CAConstants.CA_ACTIVE; }
        public boolean isExpired() { return status == CAConstants.CA_EXPIRED; }
        public boolean isRevoked() { return status == CAConstants.CA_REVOKED; }
        public boolean isExternal() { return status == CAConstants.CA_EXTERNAL; }
        public boolean isWaiting() { return status == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE; }
        public boolean isUnableToChangeState() { return isRevoked() || isExpired() || isExternal() || isWaiting(); }
        public boolean isOffline() { return !isActive() && !isExpired() && !isRevoked(); }

        public boolean isMonitoredNewState() { return monitoredNewState; }
        public void setMonitoredNewState(boolean monitoredNewState) { this.monitoredNewState = monitoredNewState; }
        public boolean isMonitored() { return monitored; }
        public int getStatus() { return status; }
        public String getName() { return name; }
        public int getCaId() { return caId; }
        public boolean isNewState() { return newState; }
        public void setNewState(boolean newState) { this.newState = newState; }
	}

    /** GUI representation of a CryptoToken and its CA(s) for the activation view */
	public class TokenAndCaActivationGuiInfo {
	    private final CryptoTokenInfo cryptoTokenInfo;
	    private final List<CaActivationGuiInfo> caActivationGuiInfos = new ArrayList<CaActivationGuiInfo>();
        private final boolean allowedActivation;
        private final boolean allowedDeactivation;
        private boolean cryptoTokenNewState;

        private TokenAndCaActivationGuiInfo(CryptoTokenInfo cryptoTokenInfo, boolean allowedActivation, boolean allowedDeactivation) {
	        this.cryptoTokenInfo = cryptoTokenInfo;
	        this.cryptoTokenNewState = cryptoTokenInfo.isActive();
            this.allowedActivation = allowedActivation;
            this.allowedDeactivation = allowedDeactivation;
	    }

	    public TokenAndCaActivationGuiInfo(Integer cryptoTokenId) {
            this.cryptoTokenInfo = new CryptoTokenInfo(cryptoTokenId, "CryptoToken id " + cryptoTokenId, false, false, NullCryptoToken.class,
                    new Properties());
            this.cryptoTokenNewState = false;
            this.allowedActivation = false;
            this.allowedDeactivation = false;
        }

        public void add(CaActivationGuiInfo caActivationGuiInfo) {
	        caActivationGuiInfos.add(caActivationGuiInfo);
	    }

        public List<CaActivationGuiInfo> getCas() { return caActivationGuiInfos; }
	    
        public int getCryptoTokenId() { return cryptoTokenInfo.getCryptoTokenId(); }
        public String getCryptoTokenName() { return cryptoTokenInfo.getName(); }
        public boolean isExisting() { return !"NullCryptoToken".equals(cryptoTokenInfo.getType()); }
        public boolean isCryptoTokenActive() { return cryptoTokenInfo.isActive(); }
        public boolean isAutoActivated() { return cryptoTokenInfo.isAutoActivation(); }
        public boolean isStateChangeDisabled() { return isAutoActivated() || (isCryptoTokenActive() && !allowedDeactivation) || (!isCryptoTokenActive() && !allowedActivation);}
        public boolean isCryptoTokenNewState() { return cryptoTokenNewState; }
        public void setCryptoTokenNewState(boolean cryptoTokenNewState) { this.cryptoTokenNewState = cryptoTokenNewState; }
	}

    /** GUI representation of a CryptoToken and its CA(s) for the activation view */
    public class TokenAndCaActivationGuiComboInfo {
        private final boolean firstCryptoTokenListing;
        private final TokenAndCaActivationGuiInfo cryptoTokenInfo;
        private final CaActivationGuiInfo caActivationGuiInfo;
        public TokenAndCaActivationGuiComboInfo(TokenAndCaActivationGuiInfo cryptoTokenInfo, CaActivationGuiInfo caActivationGuiInfo, boolean first) {
            this.cryptoTokenInfo = cryptoTokenInfo;
            this.caActivationGuiInfo = caActivationGuiInfo;
            this.firstCryptoTokenListing = first;
        }
        public boolean isFirst() { return firstCryptoTokenListing; }
        public TokenAndCaActivationGuiInfo getCryptoToken() { return cryptoTokenInfo; }
        public CaActivationGuiInfo getCa() { return caActivationGuiInfo; }
    }

	private final AuthenticationToken authenticationToken = EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject();
    private final EjbLocalHelper ejbLocalhelper = new EjbLocalHelper();
	private final CAAdminSessionLocal caAdminSession = ejbLocalhelper.getCaAdminSession();
	private final CaSessionLocal caSession = ejbLocalhelper.getCaSession(); 
	private final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = ejbLocalhelper.getCryptoTokenManagementSession();
    private final AccessControlSessionLocal accessControlSession = ejbLocalhelper.getAccessControlSession();

	private List<TokenAndCaActivationGuiComboInfo> authorizedTokensAndCas = null;
	private String authenticationcode;

	public List<TokenAndCaActivationGuiComboInfo> getAuthorizedTokensAndCas() {
	    final Map<Integer,TokenAndCaActivationGuiInfo> sortMap = new HashMap<Integer,TokenAndCaActivationGuiInfo>();
	    for (final Integer caId : caSession.getAuthorizedCAs(authenticationToken)) {
	        try {
                final CAInfo caInfo = caSession.getCAInfoInternal(caId.intValue(), null, true);
                final Integer cryptoTokenId = Integer.valueOf(caInfo.getCAToken().getCryptoTokenId());
                if (sortMap.get(cryptoTokenId)==null) {
                    // Perhaps not authorized to view the CryptoToken used by the CA, but we implicitly
                    // allow this in the current context since we are authorized to the CA.
                    final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(cryptoTokenId.intValue());
                    if (cryptoTokenInfo==null) {
                        sortMap.put(cryptoTokenId, new TokenAndCaActivationGuiInfo(cryptoTokenId));
                    } else {
                        final boolean allowedActivation = accessControlSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.ACTIVATE.resource() + '/' + cryptoTokenId);
                        final boolean allowedDeactivation = accessControlSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.DEACTIVATE.resource() + '/' + cryptoTokenId);
                        sortMap.put(cryptoTokenId, new TokenAndCaActivationGuiInfo(cryptoTokenInfo, allowedActivation, allowedDeactivation));
                    }
                }
                sortMap.get(cryptoTokenId).add(new CaActivationGuiInfo(caInfo.getStatus(), caInfo.getIncludeInHealthCheck(), caInfo.getName(), caInfo.getCAId()));
            } catch (CADoesntExistsException e) {
                throw new RuntimeException("Authorized CA Id does no longer exist.");
            }
	    }
        final TokenAndCaActivationGuiInfo[] tokenAndCasArray = sortMap.values().toArray(new TokenAndCaActivationGuiInfo[0]);
        // Sort array by CryptoToken name
        Arrays.sort(tokenAndCasArray, new Comparator<TokenAndCaActivationGuiInfo>() {
            @Override
            public int compare(TokenAndCaActivationGuiInfo o1, TokenAndCaActivationGuiInfo o2) {
                return o1.getCryptoTokenName().compareToIgnoreCase(o2.getCryptoTokenName());
            }
        });
        final List<TokenAndCaActivationGuiComboInfo> retValues = new ArrayList<TokenAndCaActivationGuiComboInfo>();
	    for (final TokenAndCaActivationGuiInfo value : tokenAndCasArray) {
	        boolean first = true;
	        final CaActivationGuiInfo[] casArray = value.getCas().toArray(new CaActivationGuiInfo[0]);
	        // Sort array by CA name
	        Arrays.sort(casArray, new Comparator<CaActivationGuiInfo>() {
	            @Override
	            public int compare(CaActivationGuiInfo o1, CaActivationGuiInfo o2) {
	                return o1.getName().compareToIgnoreCase(o2.getName());
	            }
	        });
	        for (final CaActivationGuiInfo value2 : casArray) {
	            retValues.add(new TokenAndCaActivationGuiComboInfo(value, value2, first));
	            first = false;
	        }
	    }
	    authorizedTokensAndCas = retValues;
	    return retValues;
	}

	/**
	 * Tries to activate CryptoTokens (once for each), if authentication code is present and activation is requested.
	 * Set the CA service status to the requested state for each CA.
	 */
	public void applyChanges() {
	    if (authorizedTokensAndCas==null) {
	        return;
	    }
	    for (final TokenAndCaActivationGuiComboInfo tokenAndCaCombo : authorizedTokensAndCas) {
            if (tokenAndCaCombo.isFirst()) {
                TokenAndCaActivationGuiInfo tokenAndCa = tokenAndCaCombo.getCryptoToken();
                if (log.isDebugEnabled()) {
                    log.debug("isCryptoTokenActive(): " + tokenAndCa.isCryptoTokenActive() + " isCryptoTokenNewState(): " + tokenAndCa.isCryptoTokenNewState());
                }
	            if (tokenAndCa.isCryptoTokenActive() != tokenAndCa.isCryptoTokenNewState()) {
	                if (tokenAndCa.isCryptoTokenNewState()) {
	                    // Assert that authcode is present
	                    if (authenticationcode != null && authenticationcode.length()>0) {
	                        // Activate CA's CryptoToken
	                        try {
	                            cryptoTokenManagementSession.activate(authenticationToken, tokenAndCa.getCryptoTokenId(), authenticationcode.toCharArray());
	                            log.info(authenticationToken.toString() + " activated CryptoToken " + tokenAndCa.getCryptoTokenId());
	                        } catch (CryptoTokenAuthenticationFailedException e) {
	                            super.addNonTranslatedErrorMessage("Bad authentication code.");
	                        } catch (CryptoTokenOfflineException e) {
	                            super.addNonTranslatedErrorMessage("Crypto Token is offline and cannot be activated.");
	                        } catch (AuthorizationDeniedException e) {
	                            super.addNonTranslatedErrorMessage(e.getMessage());
	                        }
	                    } else {
	                        super.addNonTranslatedErrorMessage("Authentication code required.");
	                    }
	                } else {
	                    // Deactivate CA's CryptoToken
	                    try {
	                        cryptoTokenManagementSession.deactivate(authenticationToken, tokenAndCa.getCryptoTokenId());
	                        log.info(authenticationToken.toString() + " deactivated CryptoToken " + tokenAndCa.getCryptoTokenId());
	                    } catch (AuthorizationDeniedException e) {
	                        super.addNonTranslatedErrorMessage(e.getMessage());
	                    }
	                }
	            }
	        }
	        CaActivationGuiInfo ca = tokenAndCaCombo.getCa();
	        if (ca.isActive() != ca.isNewState()) {
	            // Valid transition 1: Currently offline, become active
	            if (ca.isNewState() && ca.getStatus()==CAConstants.CA_OFFLINE) {
	                try {
	                    caAdminSession.activateCAService(authenticationToken, ca.getCaId());
	                } catch (Exception e) {
	                    super.addNonTranslatedErrorMessage(e.getMessage());
	                }
	            } 
	            // Valid transition 2: Currently online, become offline
	            if (!ca.isNewState() && ca.getStatus()==CAConstants.CA_ACTIVE) {
	                try {
	                    caAdminSession.deactivateCAService(authenticationToken, ca.getCaId());
	                } catch (Exception e) {
	                    super.addNonTranslatedErrorMessage(e.getMessage());
	                }
	            }
	        }
	        if (ca.isMonitored() != ca.isMonitoredNewState()) {
	            // Only persist changes if there are any
	            try {
	                final CAInfo caInfo = caSession.getCAInfoInternal(ca.getCaId(), null, false);
	                caInfo.setIncludeInHealthCheck(ca.isMonitoredNewState());
	                caAdminSession.editCA(authenticationToken, caInfo);
	            } catch (CADoesntExistsException e) {
	                super.addNonTranslatedErrorMessage(e.getMessage());
	            } catch (AuthorizationDeniedException e) {
	                super.addNonTranslatedErrorMessage(e.getMessage());
	            }
	        }
	        if (log.isDebugEnabled()) {
	            log.debug("caId: " + ca.getCaId() + " monitored: " + ca.isMonitored() + " newCaStatus: " + ca.isNewState());
	        }
	    }
	}

	/** @return true when there is at least one CryptoToken that can be activated. */
    public boolean isActivationCodeShown() {
        if (authorizedTokensAndCas!=null) {
            for (final TokenAndCaActivationGuiComboInfo tokenAndCa : authorizedTokensAndCas) {
                if (tokenAndCa.isFirst()) {
                    if (!tokenAndCa.getCryptoToken().isCryptoTokenActive() && !tokenAndCa.getCryptoToken().isStateChangeDisabled()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
	public void setAuthenticationCode(String authenticationcode) { this.authenticationcode = authenticationcode; }
	public String getAuthenticationCode() { return ""; }
}
