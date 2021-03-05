package org.cesecore.authentication.oauth;

import org.apache.commons.lang.StringUtils;

import java.util.Arrays;

/**
 * Utility class for OAuth Provider related operations
 *
 */
public class OAuthKeyHelper {
        
    public static void validateProvider(final OAuthKeyInfo provider, final boolean isCli) {
        validateCommonType(provider, isCli);
        if (OAuthKeyInfo.OAuthProviderType.TYPE_AZURE.getIndex() == provider.getTypeInt()) {
            validateAzureType(provider);
        } else if (OAuthKeyInfo.OAuthProviderType.TYPE_KEYCLOAK.getIndex() == provider.getTypeInt()) {
            validateKeycloakType(provider);
        } else if (OAuthKeyInfo.OAuthProviderType.TYPE_NONE.getIndex() != provider.getTypeInt()) {
            throw new MissingOAuthKeyAttributeException("The Provider Type field is mandatory for all Trusted OAuth Providers.");
        }
    }
    
    public static void validateAzureType(final OAuthKeyInfo provider) {
        if (StringUtils.isEmpty(provider.getUrl())) {
            throw new MissingOAuthKeyAttributeException("The URL field is mandatory for Trusted OAuth Providers.");
        }
        if (StringUtils.isEmpty(provider.getClient())) {
            throw new MissingOAuthKeyAttributeException("The Tenant field (use --client) is mandatory for Azure Trusted OAuth Providers.");
        }
        if (StringUtils.isEmpty(provider.getClientSecretAndDecrypt())) {
            throw new MissingOAuthKeyAttributeException("The Client Secret field is mandatory for Azure Trusted OAuth Providers.");
        }
    }
    
    public static void validateKeycloakType(final OAuthKeyInfo provider) {
        if (StringUtils.isEmpty(provider.getUrl())) {
            throw new MissingOAuthKeyAttributeException("The URL field is mandatory for Trusted OAuth Providers.");
        }
        if (StringUtils.isEmpty(provider.getClient())) {
            throw new MissingOAuthKeyAttributeException("The Client Name field is mandatory for Keycloak Trusted OAuth Providers.");
        }
        if (StringUtils.isEmpty(provider.getRealm())) {
            throw new MissingOAuthKeyAttributeException("The Realm field is mandatory for Keycloak Trusted OAuth Providers.");
        }
    }
    
    private static void validateCommonType(final OAuthKeyInfo provider, final boolean isCli) {
        if (StringUtils.isEmpty(provider.getLabel())) {
            throw new MissingOAuthKeyAttributeException("The Label field is mandatory for all Trusted OAuth Providers.");
        }
        if (!isCli && (provider.getKeys() == null || provider.getKeys().isEmpty())) {
            throw new MissingOAuthKeyAttributeException("At least one Public Key is mandatory for all Trusted OAuth Providers.");
        }
    }
}
