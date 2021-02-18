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
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriBuilder;

import org.cesecore.authentication.oauth.OAuthGrantResponseInfo;
import org.cesecore.authentication.oauth.OauthRequestHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.util.HttpTools;

/**
 * JSF Managed Bean for the OAuth login page in the RA Web. 
 */
@ManagedBean
@SessionScoped
public class RaLoginBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaLoginBean.class);
    private GlobalConfiguration globalConfiguration;
    
    private Collection<OAuthKeyInfoGui> oauthKeys = null;
    /** A random identifier used to link requests, to avoid CSRF attacks. */
    private String stateInSession = null;
    private String oauthClicked = null;

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    public class OAuthKeyInfoGui implements Serializable {
        private static final long serialVersionUID = 1L;
        String label;
        String keyId;

        public OAuthKeyInfoGui(String label, String keyId) {
            this.label = label;
            this.keyId = keyId;
        }

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
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
        OAuthKeyInfo oAuthKeyInfo = globalConfiguration.getOauthKeyByKeyIdentifier(oauthClicked);
        if (oAuthKeyInfo != null) {
            final OAuthGrantResponseInfo token = OauthRequestHelper.sendTokenRequest(oAuthKeyInfo, authCode,
                    getRedirectUri());
            if (token.compareTokenType(HttpTools.AUTHORIZATION_SCHEME_BEARER)) {
                servletRequest.getSession(true).setAttribute("ejbca.bearer.token", token);
                raAuthenticationBean.resetAuthentication();
                FacesContext.getCurrentInstance().getExternalContext().redirect("index.xhtml");
            } else {
                log.info("Received OAuth token of unsupported type '" + token.getTokenType() + "'");
            }
        } else {
            log.info("Can not find Trusted provider configurations. Key indentifier = " + oauthClicked);
        }

    }
    
    private void initOauthKeys() {
        oauthKeys = new ArrayList<>();
        initGlobalConfiguration();
        Collection<OAuthKeyInfo> oAuthKeyInfos = globalConfiguration.getOauthKeys().values();
        if (!oAuthKeyInfos.isEmpty()) {
            for (OAuthKeyInfo oauthKeyInfo : oAuthKeyInfos) {
                if (StringUtils.isNotEmpty(oauthKeyInfo.getUrl())) {
                    oauthKeys.add(new OAuthKeyInfoGui(oauthKeyInfo.getShowName(), oauthKeyInfo.getKeyIdentifier()));
                }
            }
        }
    }
    
    public Collection<OAuthKeyInfoGui> getOauthKeys() {
        return oauthKeys;
    }
    
    private String getOauthLoginUrl(OAuthKeyInfo oauthKeyInfo) {
        String url = oauthKeyInfo.getUrl();
        if (StringUtils.isNotEmpty(oauthKeyInfo.getRealm())) {
            url = new StringBuilder()
                    .append(oauthKeyInfo.getUrl()).append("/realms/")
                    .append(oauthKeyInfo.getRealm())
                    .append("/protocol/openid-connect/auth").toString();
        }
        return addParametersToUrl(oauthKeyInfo, url);
    }

    private String addParametersToUrl(OAuthKeyInfo oauthKeyInfo, String url) {
        UriBuilder uriBuilder = UriBuilder.fromUri(url);
        if (StringUtils.isNotEmpty(oauthKeyInfo.getClient())) {
            uriBuilder
                    .queryParam("client_id", oauthKeyInfo.getClient());
        }
        uriBuilder
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
        return baseUrl +"/login.xhtml";
    }
    
    private void initGlobalConfiguration() {
        globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfiguration.initializeRaWeb();
    }

    private boolean verifyStateParameter(final String state) {
        return stateInSession != null && stateInSession.equals(state);
    }

    public void clickLoginLink(String keyId) throws IOException {
        OAuthKeyInfo oAuthKeyInfo = globalConfiguration.getOauthKeyByKeyIdentifier(keyId);
        if (oAuthKeyInfo != null) {
            oauthClicked = keyId;
            String url = getOauthLoginUrl(oAuthKeyInfo);
            FacesContext.getCurrentInstance().getExternalContext().redirect(url);
        } else {
            log.info("Trusted provider info not found for keyId =" + keyId);
        }
    }
}
