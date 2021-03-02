package org.cesecore.authentication.oauth;

import org.apache.commons.lang.StringUtils;

import java.util.Arrays;

/**
 * Utility class for OAuth Provider related operations
 *
 */
public class OAuthKeyHelper {
        
    public static void validateProvider(OAuthKeyInfo provider) {
        validateCommonType(provider);
        if (OAuthKeyInfo.OAuthProviderType.TYPE_AZURE.getIndex() == provider.getTypeInt()) {
            validateAzureType(provider);
        } else if (OAuthKeyInfo.OAuthProviderType.TYPE_KEYCLOAK.getIndex() == provider.getTypeInt()) {
            validateKeycloakType(provider);
        } else {
            throw new MissingOAuthKeyAttributeException("The Provider Type field is mandatory for all Trusted OAuth Providers.");
        }
    }

    public static void validateAzureType(OAuthKeyInfo provider) {
        if (StringUtils.isEmpty(provider.getClient())) {
            throw new MissingOAuthKeyAttributeException("The Client field is mandatory for Azure Trusted OAuth Providers.");
        }
        if (StringUtils.isEmpty(provider.getClientSecretAndDecrypt())) {
            throw new MissingOAuthKeyAttributeException("The Client Secret field is mandatory for Azure Trusted OAuth Providers.");
        }
    }
    
    public static void validateKeycloakType(OAuthKeyInfo provider) {
        if (StringUtils.isEmpty(provider.getRealm())) {
            throw new MissingOAuthKeyAttributeException("The Realm field is mandatory for Keycloak Trusted OAuth Providers.");
        }
        if (StringUtils.isEmpty(provider.getUrl())) {
            throw new MissingOAuthKeyAttributeException("The URL field is mandatory for Keycloak Trusted OAuth Providers.");
        }
    }
    
    private static void validateCommonType(OAuthKeyInfo provider) {
        if (provider.getKeys()== null || provider.getKeys().isEmpty()) {
            throw new MissingOAuthKeyAttributeException("At least one The Public Key  is mandatory for all Trusted OAuth Providers.");
        }
    }
}
