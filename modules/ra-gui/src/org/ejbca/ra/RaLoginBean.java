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

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.ws.rs.core.UriBuilder;

import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;

/**
 * JSF Managed Bean for the OAuth login page in the RA Web. 
 */
@ManagedBean
@ViewScoped
public class RaLoginBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaLoginBean.class);
    private GlobalConfiguration globalConfiguration;
    
    private Collection<OAuthKeyInfoGui> oauthKeys = null;
    /** A random identifier used to link requests, to avoid CSRF attacks. */
    private String stateInSession = null;
    
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }
    
    public class OAuthKeyInfoGui implements Serializable {
        private static final long serialVersionUID = 1L;
        String label;
        String url;

        public OAuthKeyInfoGui(String label, String url) {
            this.label = label;
            this.url = url;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }
    
    public void onLoginPageLoad() {
        log.debug("Generating randomized 'state' string.");
        final byte[] stateBytes = new byte[32];
        new SecureRandom().nextBytes(stateBytes);
        stateInSession = Base64.encodeBase64URLSafeString(stateBytes);
        initOauthKeys();
    }
    
    private void initOauthKeys() {
        oauthKeys = new ArrayList<>();
        initGlobalConfiguration();
        Collection<OAuthKeyInfo> oAuthKeyInfos = globalConfiguration.getOauthKeys().values();
        if (!oAuthKeyInfos.isEmpty()) {
            for (OAuthKeyInfo oauthKeyInfo : oAuthKeyInfos) {
                if (StringUtils.isNotEmpty(oauthKeyInfo.getUrl())) {
                    String url = getOauthLoginUrl(oauthKeyInfo);
                    oauthKeys.add(new OAuthKeyInfoGui(oauthKeyInfo.getShowName(), url));
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
                .queryParam("redirect_uri", getRedirectUri(oauthKeyInfo))
                .queryParam("state", stateInSession);
        return uriBuilder.build().toString();
    }
    
    private String getRedirectUri(OAuthKeyInfo oAuthKeyInfo) {
        if (globalConfiguration == null) {
            initGlobalConfiguration();
        }
        String baseUrl = globalConfiguration.getBaseUrl(
                "https",
                WebConfiguration.getHostName(),
                WebConfiguration.getPublicHttpsPort()
        ) + globalConfiguration.getRaWebPath();
        log.info(" baseUrl " + baseUrl);
        return baseUrl + "?provider="+oAuthKeyInfo.getKeyIdentifier();
    }
    
    private void initGlobalConfiguration() {
        globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfiguration.initializeRaWeb();
    }
}
