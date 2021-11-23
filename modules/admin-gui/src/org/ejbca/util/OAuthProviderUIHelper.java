package org.ejbca.util;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.oauth.MissingOAuthKeyAttributeException;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.ejbca.ui.web.admin.configuration.SystemConfigurationOAuthKeyManager.OAuthKeyEditor;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * A utility class for validating OAuth Providers in the UI (CLI has its own class due to lack of localization)
 *
 */
public class OAuthProviderUIHelper {
    
    private static final String OAUTHKEYCONFIGURATION_FIELD_MANDATORY = "OAUTHKEYCONFIGURATION_FIELD_MANDATORY";
    
    public static void validateProvider(final OAuthKeyEditor provider) {
        validateCommonType(provider);
        if (OAuthKeyInfo.OAuthProviderType.TYPE_AZURE.getIndex() == provider.getType().getIndex()) {
            validateAzureType(provider);
        } else if (OAuthKeyInfo.OAuthProviderType.TYPE_KEYCLOAK.getIndex() == provider.getType().getIndex()) {
            validateKeycloakType(provider);
        } else if (OAuthKeyInfo.OAuthProviderType.TYPE_PINGID.getIndex() == provider.getType().getIndex()) {
            validatePingIdType(provider);
        } else if (OAuthKeyInfo.OAuthProviderType.TYPE_GENERIC.getIndex() != provider.getType().getIndex()) {
            throw new MissingOAuthKeyAttributeException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Provider Type"));
        }
    }
    
    public static void validateAzureType(final OAuthKeyEditor provider) {
        if (StringUtils.isEmpty(provider.getUrl())) {
            throw new MissingOAuthKeyAttributeException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "URL"));
        }
        if (StringUtils.isEmpty(provider.getRealm())) {
            throw new MissingOAuthKeyAttributeException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Tenant"));
        }
        if (StringUtils.isEmpty(provider.getScope())) {
            throw new MissingOAuthKeyAttributeException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Scope"));
        }
        if (StringUtils.isEmpty(provider.getClient())) {
            throw new MissingOAuthKeyAttributeException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Client"));
        }
        if (StringUtils.isEmpty(provider.getClientSecret()) && provider.getKeyBinding() == null) {
            throw new MissingOAuthKeyAttributeException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Client Secret or Key Binding"));
        }
    }
    
    public static void validateKeycloakType(final OAuthKeyEditor provider) {
        if (StringUtils.isEmpty(provider.getUrl())) {
            throw new MissingOAuthKeyAttributeException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "URL"));
        }
        if (StringUtils.isEmpty(provider.getClient())) {
            throw new MissingOAuthKeyAttributeException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Client"));
        }
        if (StringUtils.isEmpty(provider.getRealm())) {
            throw new MissingOAuthKeyAttributeException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Realm"));
        }
    }

    public static void validatePingIdType(final OAuthKeyEditor provider) {
        if (StringUtils.isEmpty(provider.getUrl())) {
            throw new MissingOAuthKeyAttributeException(
                    EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "URL"));
        }
        if (StringUtils.isEmpty(provider.getClient())) {
            throw new MissingOAuthKeyAttributeException(
                    EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Client"));
        }
        if (StringUtils.isEmpty(provider.getClientSecret())) {
            throw new MissingOAuthKeyAttributeException(
                    EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Client secret"));
        }
        if (StringUtils.isEmpty(provider.getTokenUrl())) {
            throw new MissingOAuthKeyAttributeException(
                    EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Token URL"));
        }
        if (StringUtils.isEmpty(provider.getLogoutUrl())) {
            throw new MissingOAuthKeyAttributeException(
                    EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Logout URL"));
        }
    }

    private static void validateCommonType(final OAuthKeyEditor provider) {
        if (StringUtils.isEmpty(provider.getLabel())) {
            throw new MissingOAuthKeyAttributeException(
                    EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Label"));
        }
        if (!provider.isAudienceCheckDisabled() && StringUtils.isEmpty(provider.getAudience())) {
            throw new MissingOAuthKeyAttributeException(
                    EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(OAUTHKEYCONFIGURATION_FIELD_MANDATORY, false, "Audience"));
        }
    }
}
