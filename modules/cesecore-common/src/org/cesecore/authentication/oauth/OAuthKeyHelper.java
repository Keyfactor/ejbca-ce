package org.cesecore.authentication.oauth;

/**
 * Utility class for OAuth Provider related operations
 *
 */
public class OAuthKeyHelper {
        
    public static void validateProvider(OAuthKeyInfo provider) {
        validateCommonType(provider);
        if (OAuthKeyInfo.OAuthProviderType.TYPE_AZURE.equals(provider.getType())) {
            validateAzureType(provider);
        } else if (OAuthKeyInfo.OAuthProviderType.TYPE_KEYCLOAK.equals(provider.getType())) {
            validateKeycloakType(provider);
        } else {
            throw new MissingOAuthKeyAttributeException("The Provider Type field is mandatory for all Trusted OAuth Providers.");
        }
    }

    public static void validateAzureType(OAuthKeyInfo provider) {
        if (provider.getClient().isEmpty()) {
            throw new MissingOAuthKeyAttributeException("The Client field is mandatory for Azure Trusted OAuth Providers.");
        }
        // Uncomment once the client secret gets merged to the epic branch
        /*if (provider.getClientSecret().isEmpty()) {
            throw new MissingOAuthKeyAttributeException("The Client Secret field is mandatory for Azure Trusted OAuth Provider.");
        }*/
    }
    
    public static void validateKeycloakType(OAuthKeyInfo provider) {
        if (provider.getRealm().isEmpty()) {
            throw new MissingOAuthKeyAttributeException("The Realm field is mandatory for Keycloak Trusted OAuth Providers.");
        }
        if (provider.getUrl().isEmpty()) {
            throw new MissingOAuthKeyAttributeException("The URL field is mandatory for Keycloak Trusted OAuth Providers.");
        }
    }
    
    private static void validateCommonType(OAuthKeyInfo provider) {
        if (provider.getKeyIdentifier().isEmpty()) {
            throw new MissingOAuthKeyAttributeException("The Key Identifier field is mandatory for all Trusted OAuth Providers.");
        }
        if (provider.getPublicKeyBytes() == null) {
            throw new MissingOAuthKeyAttributeException("The Public Key field is mandatory for all Trusted OAuth Providers.");
        }
    }
}
