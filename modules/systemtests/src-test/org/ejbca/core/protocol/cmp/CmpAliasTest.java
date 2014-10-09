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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.WebConfiguration;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CmpAliasTest extends CmpTestCase {
    
    private static final Logger log = Logger.getLogger(CmpAliasTest.class);

    private final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    
    private final String baseResource = "publicweb/cmp";
    private final String httpReqPath;

    public CmpAliasTest() {
        final String httpServerPubHttp = SystemTestsConfiguration.getRemotePortHttp(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        final String httpServerHost = SystemTestsConfiguration.getRemoteHost(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        this.httpReqPath = "http://" + httpServerHost + ":" + httpServerPubHttp + "/ejbca";
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Sends a CMP request with the alias requestAlias in the URL and expects a CMP error message 
     * that extractedAlias does not  exist.
     * 
     * @param requestAlias the alias that is  specified in the URL
     * @param extractedAlias the alias that EJBCA will use to handle the CMP request
     * @throws Exception
     */
    private void sendCmpRequest(CmpConfiguration cmpconfig, String requestAlias, String extractedAlias) throws Exception {
        
        if(cmpconfig.aliasExists(extractedAlias)) {
            cmpconfig.renameAlias(extractedAlias, "backUpAlias" + extractedAlias + "ForAliasTesting001122334455");
            this.globalConfigurationSession.saveConfiguration(ADMIN, cmpconfig, CmpConfiguration.CMP_CONFIGURATION_ID);
        }
        
        try {
            String urlString = this.httpReqPath + '/' + this.baseResource;
            if(requestAlias != null) {
                urlString += "/" + requestAlias; 
            }
            log.info("http URL: " + urlString);
            URL url = new URL(urlString);
            final HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/pkixcmp");
            con.connect();
            assertEquals("Unexpected HTTP response code.", 200, con.getResponseCode()); // OK response (will use alias "alias123")

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            // This works for small requests, and CMP requests are small enough
            InputStream in = con.getInputStream();
            int b = in.read();
            while (b != -1) {
                baos.write(b);
                b = in.read();
            }
            baos.flush();
            in.close();
            byte[] respBytes = baos.toByteArray();
            assertNotNull(respBytes);
            assertTrue(respBytes.length > 0);

            ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(respBytes));
            PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
            assertNotNull(respObject);
            
            final PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            final String expectedErrMsg = "Wrong URL. CMP alias '" + extractedAlias + "' does not exist";
            assertEquals(expectedErrMsg, errMsg);
            inputStream.close();
        } finally {
            if(cmpconfig.aliasExists("backUpAlias" + extractedAlias + "ForAliasTesting001122334455")) {
                cmpconfig.renameAlias("backUpAlias" + extractedAlias + "ForAliasTesting001122334455", extractedAlias);
                this.globalConfigurationSession.saveConfiguration(ADMIN, cmpconfig, CmpConfiguration.CMP_CONFIGURATION_ID);
            }
        }
    }
    
    
    /**
     * Tests that the right configuration alias is extracted from the CMP URL. 
     * 
     * A CMP request for a non-existing alias is sent. Expected an error message caused by the absence of the expected CMP alias 
     * 
     * @throws Exception
     */
    @Test
    public void test01Access() throws Exception {
        log.trace(">test01Access()");
        
        CmpConfiguration cmpConfig = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        
        sendCmpRequest(cmpConfig, "alias123", "alias123"); // "alias123" in the request causes Ejbca to use "alias123" as CMP alias
        sendCmpRequest(cmpConfig, "123", "123"); // "123" in the request causes Ejbca to use "123" as CMP alias
        sendCmpRequest(cmpConfig, "", "cmp"); // No alias in the request causes Ejbca to use "cmp" (the default alias) as CMP alias
        sendCmpRequest(cmpConfig, null, "cmp"); // No alias in the request causes Ejbca to use "cmp" (the default alias) as CMP alias
        sendCmpRequest(cmpConfig, "alias??&!!foo", "alias"); // Specifying alias with non-alphanumeric characters cause Ejbca to use, 
                                                             // as CMP alias, a substring of the first alphanumeric characters, in this 
                                                             // case: alias
        sendCmpRequest(cmpConfig, "??##!!&", "cmp"); // Specifying alias with non-alphanumeric characters cause Ejbca to use, 
                                                     // as CMP alias, a substring of the first alphanumeric characters, in this 
                                                     // case: empty string, which means that the default alias "cmp" will be used

        log.trace("<test01Access()");
    }

    @Test
    public void test02CmpAliasTest() {
        CmpConfiguration cmpConfig = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);

        // Test adding an alias
        String alias = "CmpURLTestCmpConfigAlias";
        while(cmpConfig.aliasExists(alias)) {
            alias += "0";
        }
        cmpConfig.addAlias(alias);
        assertTrue("Failed to add alias: " + alias, cmpConfig.aliasExists(alias));
        assertFalse("Alias '" + alias + "' was not initialized correctly", cmpConfig.getRAMode(alias));
        
        // Test cloning an alias
        String clonealias = alias + "CloneAlias";
        while(cmpConfig.aliasExists(clonealias)) {
            clonealias += "0";
        }
        cmpConfig.cloneAlias(alias, clonealias);
        assertTrue(cmpConfig.aliasExists(alias));
        assertTrue(cmpConfig.aliasExists(clonealias));
        cmpConfig.setRAMode(alias, true);
        assertTrue(cmpConfig.getRAMode(alias));
        assertFalse(cmpConfig.getRAMode(clonealias));
        cmpConfig.cloneAlias(clonealias, alias);
        assertTrue(cmpConfig.aliasExists(alias));
        assertTrue(cmpConfig.aliasExists(clonealias));
        assertTrue(cmpConfig.getRAMode(alias));
        assertFalse(cmpConfig.getRAMode(clonealias));
        
        // Test renaming an alias
        String renamealias = alias + "RenameAlias";
        while(cmpConfig.aliasExists(renamealias)) {
            renamealias += "0";
        }
        cmpConfig.renameAlias(alias, renamealias);
        assertTrue(cmpConfig.aliasExists(renamealias));
        assertFalse(cmpConfig.aliasExists(alias));
        assertTrue(cmpConfig.getRAMode(renamealias));
        cmpConfig.renameAlias(renamealias, clonealias);
        assertTrue(cmpConfig.aliasExists(renamealias));
        assertTrue(cmpConfig.aliasExists(clonealias));
        assertTrue(cmpConfig.getRAMode(renamealias));
        assertFalse(cmpConfig.getRAMode(clonealias));
        
        //Test removing alias
        cmpConfig.removeAlias(alias);
        cmpConfig.removeAlias(clonealias);
        cmpConfig.removeAlias(renamealias);
        assertFalse(cmpConfig.aliasExists(alias));
        assertFalse(cmpConfig.aliasExists(clonealias));
        assertFalse(cmpConfig.aliasExists(renamealias));
    }
   
    @Test
    public void test03AliasTooLongTest() throws Exception {
        
        String longAlias = "abcdefghijklmnopqrstuvwxyz0123456789"; 
        String urlString = this.httpReqPath + '/' + this.baseResource + '/' + longAlias; 
        log.info("http URL: " + urlString);
        URL url = new URL(urlString);
        final HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-type", "application/pkixcmp");
        con.connect();
        assertEquals("Unexpected HTTP response code.", 400, con.getResponseCode()); // 400 = HttpServletResponse.SC_BAD_REQUEST
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

}
