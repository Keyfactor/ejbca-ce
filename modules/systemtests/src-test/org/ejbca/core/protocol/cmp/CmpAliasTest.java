/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CmpAliasTest extends CmpTestCase {
    
    private static final Logger log = Logger.getLogger(CmpAliasTest.class);

    private ConfigurationSessionRemote confSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private GlobalConfigurationSessionRemote globalConfSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    
    private String baseResource = "publicweb/cmp";
    private String httpReqPath;
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
        String httpServerPubHttp = confSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP);
        String CMP_HOST = confSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME);
        httpReqPath = "http://" + CMP_HOST + ":" + httpServerPubHttp + "/ejbca";
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Tests the CMP URLs with configuration alias
     * @throws Exception
     */
    @Test
    public void test01Access() throws Exception {
        log.trace(">test01Access()");
        
        String urlString = httpReqPath + '/' + baseResource + "/alias123"; 
        log.info("http URL: " + urlString);
        URL url = new URL(urlString);
        final HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-type", "application/pkixcmp");
        con.connect();
        assertEquals("Unexpected HTTP response code.", 200, con.getResponseCode()); // OK response (will use alias "alias123")
        
        urlString = httpReqPath + '/' + baseResource + "/123"; 
        log.info("http URL: " + urlString);
        url = new URL(urlString);
        final HttpURLConnection con2 = (HttpURLConnection) url.openConnection();
        con2.setDoOutput(true);
        con2.setRequestMethod("POST");
        con2.setRequestProperty("Content-type", "application/pkixcmp");
        con2.connect();
        assertEquals("Unexpected HTTP response code.", 200, con2.getResponseCode()); // OK response (will use alias "123")
        
        urlString = httpReqPath + '/' + baseResource + "/"; 
        log.info("http URL: " + urlString);
        url = new URL(urlString);
        final HttpURLConnection con3 = (HttpURLConnection) url.openConnection();
        con3.setDoOutput(true);
        con3.setRequestMethod("POST");
        con3.setRequestProperty("Content-type", "application/pkixcmp");
        con3.connect();
        assertEquals("Unexpected HTTP response code.", 200, con3.getResponseCode()); // OK response (will use alias "cmp")
        
        urlString = httpReqPath + '/' + baseResource; 
        log.info("http URL: " + urlString);
        url = new URL(urlString);
        final HttpURLConnection con5 = (HttpURLConnection) url.openConnection();
        con5.setDoOutput(true);
        con5.setRequestMethod("POST");
        con5.setRequestProperty("Content-type", "application/pkixcmp");
        con5.connect();
        assertEquals("Unexpected HTTP response code.", 200, con5.getResponseCode()); // OK response (will use alias "cmp")
        
        urlString = httpReqPath + '/' + baseResource + "/alias??&!!foo"; 
        log.info("http URL: " + urlString);
        url = new URL(urlString);
        final HttpURLConnection con6 = (HttpURLConnection) url.openConnection();
        con6.setDoOutput(true);
        con6.setRequestMethod("POST");
        con6.setRequestProperty("Content-type", "application/pkixcmp");
        con6.connect();
        assertEquals("Unexpected HTTP response code.", 200, con6.getResponseCode()); // OK response (will use alias "alias")
        
        urlString = httpReqPath + '/' + baseResource + "/??##!!&"; 
        log.info("http URL: " + urlString);
        url = new URL(urlString);
        final HttpURLConnection con7 = (HttpURLConnection) url.openConnection();
        con7.setDoOutput(true);
        con7.setRequestMethod("POST");
        con7.setRequestProperty("Content-type", "application/pkixcmp");
        con7.connect();
        assertEquals("Unexpected HTTP response code.", 200, con7.getResponseCode()); // OK response (will use alias "cmp")
        
        log.trace("<test01Access()");
    }

    @Test
    public void test02CmpAliasTest() {
        CmpConfiguration cmpConfig = (CmpConfiguration) globalConfSession.getCachedConfiguration(Configuration.CMPConfigID);

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
    public void test03NonExistingAlias() throws Exception {
        
        String urlString = httpReqPath + '/' + baseResource + "/noneExistingAlias"; 
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
        try {
            PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
            assertNotNull(respObject);

            final PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            final String expectedErrMsg = "Wrong URL. CMP alias 'noneExistingAlias' does not exist";
            assertEquals(expectedErrMsg, errMsg);
        } finally {
            inputStream.close();
        }
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

}