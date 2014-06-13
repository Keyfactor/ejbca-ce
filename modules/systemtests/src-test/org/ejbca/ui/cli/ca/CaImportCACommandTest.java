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
package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CaImportCACommandTest {

    private static final String CA_NAME = "CaImportCACommandTest";
    private static final String CA_DN = "CN=" + CA_NAME;
    private static final String KEYSTORE_PASSWORD = "foo123";
    private static final String KEY_ALIAS = "test";

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);

    private X509CA ca;
    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            CaChangeCertProfileCommand.class.getSimpleName());

    private final CaImportCACommand command = new CaImportCACommand();
    private File keyStoreFile;

    @Before
    public void setup() throws Exception {
        keyStoreFile = File.createTempFile("test", null);
        ca = CaTestUtils.createTestX509CA(CA_DN, KEYSTORE_PASSWORD.toCharArray(), false);
        caSession.addCA(authenticationToken, ca);
        byte[] p12 = caAdminSession.exportCAKeyStore(authenticationToken, CA_NAME, KEYSTORE_PASSWORD, KEYSTORE_PASSWORD, KEY_ALIAS, KEY_ALIAS);
        FileOutputStream outputStream = new FileOutputStream(keyStoreFile);
        try { 
            outputStream.write(p12);
        } finally {
            outputStream.close();
        }
        try {
            caSession.removeCA(authenticationToken, caSession.getCAInfo(authenticationToken, CA_NAME).getCAId());
        } catch(Exception e) {
            // NOPMD Ignore
        }
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        if (keyStoreFile != null) {
            FileTools.delete(keyStoreFile);
        }
        try {
            caSession.removeCA(authenticationToken, caSession.getCAInfo(authenticationToken, CA_NAME).getCAId());
        } catch(Exception e) {
            // NOPMD Ignore
        }
    }

    @Test
    public void testSoftKey() throws CertificateException, IOException, CADoesntExistsException, AuthorizationDeniedException {
        String[] args = new String[] { ca.getName(), keyStoreFile.getAbsolutePath(), CaImportCACommand.KEYSTORE_PASSWORD_KEY, KEYSTORE_PASSWORD };
        command.execute(args);
        //Verify that CA is imported
        assertTrue("No CA was imported", caSession.existsCa(caSession.getCAInfo(authenticationToken, CA_NAME).getCAId()));
    }

}
