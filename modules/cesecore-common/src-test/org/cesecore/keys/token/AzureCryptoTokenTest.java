/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Makes some basic tests on Azure Crypto Token class
 * TODO: mock Azure REST API to perform REST API tests
 */
public class AzureCryptoTokenTest extends CryptoTokenTestBase {

    @Test
    public void testKeyVaultNameCheck() throws Exception {
        AzureCryptoToken.checkAliasName("abcde123ABCDEFf123456");
        AzureCryptoToken.checkAliasName("abcde123ABCDEF-f123456");            
        try {
            AzureCryptoToken.checkAliasName("abcde123ABCDEF.f123456");            
            fail("Should have thrown IllegalArgumentException with a dot in the alias");
        } catch (IllegalArgumentException e) {} // NOPMD: expected
        try {
            AzureCryptoToken.checkAliasName("abcde123ABCDEF/f123456");            
            fail("Should have thrown IllegalArgumentException with a slash in the alias");
        } catch (IllegalArgumentException e) {} // NOPMD: expected
        try {
            AzureCryptoToken.checkAliasName("abcde123ABCDEF$f123456");            
            fail("Should have thrown IllegalArgumentException with a $ in the alias");
        } catch (IllegalArgumentException e) {} // NOPMD: expected

        AzureCryptoToken.checkVaultName("abcde123ABCDEFf123456");
        AzureCryptoToken.checkVaultName("abcde123ABCDEF-f123456");            
        AzureCryptoToken.checkVaultName("abcde123ABCDEF.f123456");            
        try {
            AzureCryptoToken.checkVaultName("abcde123ABCDEF/f123456");            
            fail("Should have thrown IllegalArgumentException with a slash in the alias");
        } catch (IllegalArgumentException e) {} // NOPMD: expected
        try {
            AzureCryptoToken.checkVaultName("abcde123ABCDEF$f123456");            
            fail("Should have thrown IllegalArgumentException with a $ in the alias");
        } catch (IllegalArgumentException e) {} // NOPMD: expected
    }
    
    @Test
    public void testKeyVaultURL() throws Exception {
        String url = AzureCryptoToken.createFullKeyURL("myalias", "ejbca-vault");
        assertEquals("URL is not the expected", "https://ejbca-vault.vault.azure.net/keys/myalias", url);
        url = AzureCryptoToken.createFullKeyURL("myalias", "ejbca-vault.vault.azure.net");
        assertEquals("URL is not the expected", "https://ejbca-vault.vault.azure.net/keys/myalias", url);
        url = AzureCryptoToken.createFullKeyURL("myalias", "ejbca-vault.primekey.vault.se");
        assertEquals("URL is not the expected", "https://ejbca-vault.primekey.vault.se/keys/myalias", url);
        url = AzureCryptoToken.createFullKeyURL(null, "ejbca-vault");
        assertEquals("URL is not the expected", "https://ejbca-vault.vault.azure.net/keys", url);
        url = AzureCryptoToken.createFullKeyURL(null, null);
        assertEquals("URL is not the expected", "https://null.vault.azure.net/keys", url);
        url = AzureCryptoToken.createFullKeyURL("myalias", null);
        assertEquals("URL is not the expected", "https://null.vault.azure.net/keys/myalias", url);
        // CreateFullKeyURL does not make any checks
        url = AzureCryptoToken.createFullKeyURL("myalias", "ejbca-vault/");
        assertEquals("URL is not the expected", "https://ejbca-vault/.vault.azure.net/keys/myalias", url);
        url = AzureCryptoToken.createFullKeyURL("myalias", "ejbca-vault.primekey.vault.se/");
        assertEquals("URL is not the expected", "https://ejbca-vault.primekey.vault.se//keys/myalias", url);
    }

    @Override
    protected String getProvider() {
        // TODO Auto-generated method stub
        return null;
    }

}
