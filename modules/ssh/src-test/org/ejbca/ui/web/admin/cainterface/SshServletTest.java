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
package org.ejbca.ui.web.admin.cainterface;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.ssh.SshCa;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.ssh.util.SshCaTestUtils;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * System tests for the SSH servlet
 * 
 * @version $Id$
 *
 */
public class SshServletTest {

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SshServletTest"));

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Test
    public void testGetSshPublicKey() throws MalformedURLException, IOException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, AuthorizationDeniedException, NoSuchSlotException,
            OperatorCreationException, CertificateException, CAExistsException, InvalidKeyException, InvalidAlgorithmParameterException,
            InvalidAlgorithmException {
        final String caName = "testGetSshPublicKey";
        
        SshCa sshCa = SshCaTestUtils.addSshCa(caName, "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        try {
            URL url = getUrl();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            // we are going to do a POST
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            // POST it
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            OutputStream os = connection.getOutputStream();
            os.write((SshServlet.NAME_PROPERTY + "=" + caName).getBytes("UTF-8"));
            os.close();
            assertEquals("Response code", 200, connection.getResponseCode());
            InputStream is = connection.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            String response = "";
            while (br.ready()) {
                response += br.readLine();
            }
            //Verify that we received a correct RSA key
            assertTrue("Exported public key did not contain RSA prefix.", response.startsWith("ssh-rsa "));
            assertTrue("Exported public key BASE64 did not contain RSA prefix.", response.contains("AAAAB3NzaC1yc2EA"));
            assertTrue("Exported public key did not end with comment.", response.endsWith(caName));
        } finally {
            CaTestUtils.removeCa(internalAdmin, sshCa.getCAInfo());
        }
    }

    private URL getUrl() throws MalformedURLException, IOException {
        final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class,
                EjbRemoteHelper.MODULE_TEST);
        String port = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP);
        final String remotePort = SystemTestsConfiguration.getRemotePortHttp(port);
        final String remoteHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        final String contextRoot = "/ejbca/ssh";
        return new URL("http://" + remoteHost + ":" + remotePort + contextRoot);
    }
}
