package org.cesecore.authentication.oauth;

import org.apache.commons.lang.StringUtils;

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
        // Uncomment once the client secret gets merged to the epic branch
        /*if (StringUtils.isEmpty(provider.getClientSecret())) {
            throw new MissingOAuthKeyAttributeException("The Client Secret field is mandatory for Azure Trusted OAuth Provider.");
        }*/
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
        if (StringUtils.isEmpty(provider.getKeyIdentifier())) {
            throw new MissingOAuthKeyAttributeException("The Key Identifier field is mandatory for all Trusted OAuth Providers.");
        }
        if (provider.getPublicKeyBytes() == null) {
            throw new MissingOAuthKeyAttributeException("The Public Key field is mandatory for all Trusted OAuth Providers.");
        }
    }
}
