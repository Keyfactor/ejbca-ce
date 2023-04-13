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

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import javax.ejb.EJB;
import javax.enterprise.context.SessionScoped;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.UriBuilder;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthGrantResponseInfo;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.oauth.OauthRequestHelper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.KeyBindingFinder;
import org.cesecore.keybind.KeyBindingNotFoundException;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.util.HttpTools;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * JSF Managed Bean for the OAuth login page in the RA Web. 
 */
@Named
@SessionScoped
public class RaLoginBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaLoginBean.class);
    private GlobalConfiguration globalConfiguration;
    private OAuthConfiguration oAuthConfiguration;

    private Collection<OAuthKeyInfoGui> oauthKeys = null;
    /** A random identifier used to link requests, to avoid CSRF attacks. */
    private String stateInSession = null;
    private String oauthClicked = null;

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoToken;
    @EJB
    private CertificateStoreSessionLocal certificateStoreLocal;
    @EJB
    private InternalKeyBindingMgmtSessionLocal internalKeyBindings;

    @Inject
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    public class OAuthKeyInfoGui implements Serializable {
        private static final long serialVersionUID = 1L;
        String label;

        public OAuthKeyInfoGui(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }
    }
    
    public void onLoginPageLoad() throws IOException {
        HttpServletRequest servletRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        final Map<String, String> params = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap();
        final String authCode = params.get("code");
        final String state = params.get("state");
        if (StringUtils.isNotEmpty(state)) {
            if (verifyStateParameter(state)) {
                if(StringUtils.isNotEmpty(authCode)) {
                    requestTokenUsingCode(servletRequest, params);
                }
            } else {
                log.info("Received 'code' parameter without valid 'state' parameter.");
            }
        } else {
            log.debug("Generating randomized 'state' string.");
            final byte[] stateBytes = new byte[32];
            new SecureRandom().nextBytes(stateBytes);
            stateInSession = Base64.encodeBase64URLSafeString(stateBytes);
            initOauthKeys();
        }
    }

    private void requestTokenUsingCode(HttpServletRequest servletRequest, Map<String, String> params) throws IOException {
        log.debug("Received authorization code. Requesting token from authorization server.");
        final String authCode = params.get("code");
        if (globalConfiguration == null) {
            initGlobalConfiguration();
        }
        OAuthKeyInfo oAuthKeyInfo = oAuthConfiguration.getOauthKeyByLabel(oauthClicked);
        if (oAuthKeyInfo != null) {
            try {
                OauthRequestHelper oauthRequestHelper = new OauthRequestHelper(new KeyBindingFinder(
                        internalKeyBindings, certificateStoreLocal, cryptoToken));
                OAuthGrantResponseInfo token = oauthRequestHelper.sendTokenRequest(oAuthKeyInfo, authCode, getRedirectUri());
                if (token.compareTokenType(HttpTools.AUTHORIZATION_SCHEME_BEARER)) {
                    servletRequest.getSession(true).setAttribute("ejbca.bearer.token", token.getAccessToken());
                    servletRequest.getSession(true).setAttribute("ejbca.refresh.token", token.getRefreshToken());
                    raAuthenticationBean.resetAuthentication();
                    FacesContext.getCurrentInstance().getExternalContext().redirect("index.xhtml");
                } else {
                    log.info("Received OAuth token of unsupported type '" + token.getTokenType() + "'");
                }
            } catch (CryptoTokenOfflineException | KeyBindingNotFoundException e) {
                log.info("Error signing oauth token request for token " + oauthClicked, e);
            }
        } else {
            log.info("Can not find Trusted provider configurations. Key indentifier = " + oauthClicked);
        }

    }

    private void initOauthKeys() {
        StringBuilder providerUrls = new StringBuilder();
        oauthKeys = new ArrayList<>();
        initGlobalConfiguration();
        if (oAuthConfiguration != null) {
            Collection<OAuthKeyInfo> oAuthKeyInfos = oAuthConfiguration.getOauthKeys().values();
            if (!oAuthKeyInfos.isEmpty()) {
                for (OAuthKeyInfo oauthKeyInfo : oAuthKeyInfos) {
                    if (StringUtils.isNotEmpty(oauthKeyInfo.getUrl())) {
                        oauthKeys.add(new OAuthKeyInfoGui(oauthKeyInfo.getLabel()));
                        providerUrls.append(oauthKeyInfo.getUrl()).append(" ");
                    }
                }
                replaceHeader(providerUrls.toString());
            }
        }
    }
    
    public Collection<OAuthKeyInfoGui> getOauthKeys() {
        return oauthKeys;
    }
    
    private String getOauthLoginUrl(OAuthKeyInfo oauthKeyInfo) {
        String url = oauthKeyInfo.getOauthLoginUrl();
        return addParametersToUrl(oauthKeyInfo, url);
    }

    private String addParametersToUrl(OAuthKeyInfo oauthKeyInfo, String url) {
        UriBuilder uriBuilder = UriBuilder.fromUri(url);
        String scope = "openid";
        if (oauthKeyInfo.getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_AZURE)) {
            scope += " offline_access " + oauthKeyInfo.getScope();
        }
        if (oauthKeyInfo.getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_KEYCLOAK) && !oauthKeyInfo.isAudienceCheckDisabled()) {
            scope += " " + oauthKeyInfo.getAudience();
        }
        if (oauthKeyInfo.getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_PINGID) ||oauthKeyInfo.getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_GENERIC)){
            scope += " " + oauthKeyInfo.getScope();
        }
        uriBuilder
                .queryParam("scope", scope)
                .queryParam("client_id", oauthKeyInfo.getClient())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", getRedirectUri())
                .queryParam("state", stateInSession);
        return uriBuilder.build().toString();
    }
    
    private String getRedirectUri() {
        if (globalConfiguration == null) {
            initGlobalConfiguration();
        }
        String baseUrl = globalConfiguration.getBaseUrl(
                "https",
                WebConfiguration.getHostName(),
                WebConfiguration.getPublicHttpsPort()
        ) + globalConfiguration.getRaWebPath();
        if (!baseUrl.endsWith("/")) {
            baseUrl += "/";
        }
        return baseUrl +"login.xhtml";
    }
    
    private void initGlobalConfiguration() {
        oAuthConfiguration = raMasterApi.getGlobalConfiguration(OAuthConfiguration.class);
        // Get the local RA configuration, because we want to calculate the URL to the RA, not the CA
        globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfiguration.initializeRaWeb();
    }

    private boolean verifyStateParameter(final String state) {
        return stateInSession != null && stateInSession.equals(state);
    }

    public void clickLoginLink(String keyLabel) throws IOException {
        OAuthKeyInfo oAuthKeyInfo = oAuthConfiguration.getOauthKeyByLabel(keyLabel);
        if (oAuthKeyInfo != null) {
            oauthClicked = keyLabel;
            String url = getOauthLoginUrl(oAuthKeyInfo);
            FacesContext.getCurrentInstance().getExternalContext().redirect(url);
        } else {
            log.info("Trusted provider info not found for keyId =" + keyLabel);
        }
    }

    private void replaceHeader(String urls) {
        HttpServletResponse httpResponse = (HttpServletResponse)FacesContext.getCurrentInstance().getExternalContext().getResponse();
        String header = httpResponse.getHeader("Content-Security-Policy");
        header = header.replace("form-action 'self'", "form-action " + urls + "'self'");
        httpResponse.setHeader("Content-Security-Policy", header);
        httpResponse.setHeader("X-Content-Security-Policy", header);
    }
}
