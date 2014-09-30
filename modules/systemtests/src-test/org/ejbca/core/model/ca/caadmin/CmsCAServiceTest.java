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

package org.ejbca.core.model.ca.caadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.BaseSigningCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the CMS Extended CA Service
 * 
 * @version $Id$
 */
public class CmsCAServiceTest extends CaTestCase {

    private byte[] doc = "foo123".getBytes();

    private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CmsCAServiceTest"));

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    @BeforeClass
    public static void beforeClass() {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
    }

    public String getRoleName() {
        return "CmsCAServiceTest";
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();

    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Test
    public void testCmsCAServiceNotActive() throws Exception {
        // No certificates should have been generated at this point
        final CAInfo cainfo = caSession.getCAInfo(admin, "TEST");
        final Collection<ExtendedCAServiceInfo> svcinfos = cainfo.getExtendedCAServiceInfos();
        assertFalse("cainfo contained no extended service infos", svcinfos.isEmpty());
        for (ExtendedCAServiceInfo svcinfo : svcinfos) {
            if (svcinfo instanceof CmsCAServiceInfo) {
                final BaseSigningCAServiceInfo signinfo = (BaseSigningCAServiceInfo)svcinfo;
                assertEquals("Status should be INACTIVE initially", ExtendedCAServiceInfo.STATUS_INACTIVE, signinfo.getStatus());
                assertNull("No CMS certificate should have been generated until it has been activated", signinfo.getCertificatePath());
            }
        }
        
        // First try a request when the service is not active
        CmsCAServiceRequest request = new CmsCAServiceRequest(doc, CmsCAServiceRequest.MODE_SIGN);
        try {
            caAdminSession.extendedService(admin, getTestCAId(), request);
            fail("extended CA service should not have been active");
        } catch (ExtendedCAServiceNotActiveException e) {
        	// NOPMD
        }
    }

    @Test
    public void testActivateCmsCAService() throws Exception {
        // Activate the CMS service in the CA
        CAInfo cainfo = caSession.getCAInfo(admin, "TEST");
        ArrayList<ExtendedCAServiceInfo> newlist = new ArrayList<ExtendedCAServiceInfo>();
        newlist.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE, false));
        cainfo.setExtendedCAServiceInfos(newlist);
        caAdminSession.editCA(admin, cainfo);
        // Did it become active?
        cainfo = caSession.getCAInfo(admin, "TEST");
        Collection<ExtendedCAServiceInfo> infos = cainfo.getExtendedCAServiceInfos();
        boolean ok = false;
        for (ExtendedCAServiceInfo info : infos) {
			if (info.getType() == ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE) {
				if (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
					ok = true;
				}
			}
		}
        assertTrue("extended CA service should have been activated", ok);
    }

    @Test
    public void testCmsCAServiceActive() throws Exception {
    	
    	// Activate the service first
    	testActivateCmsCAService();
    	
        CmsCAServiceRequest request = new CmsCAServiceRequest(doc, CmsCAServiceRequest.MODE_SIGN);
        CmsCAServiceResponse resp = null;
        // Try the request again
        boolean active = true;
        try {
            resp = (CmsCAServiceResponse) caAdminSession.extendedService(admin, getTestCAId(), request);
        } catch (ExtendedCAServiceNotActiveException e) {
            active = false;
        }
        // By default the CA service is not active
        assertTrue(active);

        assertNotNull(resp);
        byte[] respdoc = resp.getCmsDocument();
        assertNotNull(resp);
        CMSSignedData csd = new CMSSignedData(respdoc);
        SignerInformationStore infoStore = csd.getSignerInfos();
        @SuppressWarnings("unchecked")
        Collection<SignerInformation> signers = infoStore.getSigners();
        Iterator<SignerInformation> iter = signers.iterator();
        if (iter.hasNext()) {
            SignerInformation si = iter.next();
            assertNotNull(si);
            // log.info("Digest alg is: "+si.getDigestAlgOID());
            assertEquals(CMSSignedGenerator.DIGEST_SHA1, si.getDigestAlgOID());
            SignerId sid = si.getSID();
            // log.info(sid.toString());
            X500Name issuer = sid.getIssuer();
            assertNotNull(issuer);
            assertEquals("CN=TEST", issuer.toString());
        }
        CertStore store = csd.getCertificatesAndCRLs("Collection", "BC");
        Collection<? extends Certificate> certs = store.getCertificates(null);
        assertEquals(2, certs.size());

        CMSProcessable cp = csd.getSignedContent();
        Object o = cp.getContent();
        byte[] ob = (byte[]) o;
        assertEquals(new String(doc), new String(ob));
    }

    @Test
    public void testCmsCAEncryptDecrypt() throws Exception {
    	// Activate the service first
    	testActivateCmsCAService();
    	
        CmsCAServiceRequest request = new CmsCAServiceRequest(doc, CmsCAServiceRequest.MODE_ENCRYPT);
        CmsCAServiceResponse resp = null;
        // Try the request again
        boolean active = true;
        try {
            resp = (CmsCAServiceResponse) caAdminSession.extendedService(admin, getTestCAId(), request);
        } catch (ExtendedCAServiceNotActiveException e) {
            active = false;
        }
        // By default the CA service is not active
        assertTrue(active);

        assertNotNull(resp);
        byte[] respdoc = resp.getCmsDocument();
        assertNotNull(respdoc);

        assertFalse(Arrays.equals(respdoc, doc));

        request = new CmsCAServiceRequest(respdoc, CmsCAServiceRequest.MODE_DECRYPT);

        // Try the request again
        active = true;
        try {
            resp = (CmsCAServiceResponse) caAdminSession.extendedService(admin, getTestCAId(), request);
        } catch (ExtendedCAServiceNotActiveException e) {
            active = false;
        }
        // By default the CA service is not active
        assertTrue(active);

        assertNotNull(resp);
        respdoc = resp.getCmsDocument();
        assertNotNull(respdoc);

        assertTrue(Arrays.equals(respdoc, doc));
    }

    @Test
    public void testDeActivateCmsCAService() throws Exception {
        // Deactivate the CMS service in the CA
        CAInfo cainfo = caSession.getCAInfo(admin, "TEST");
        ArrayList<ExtendedCAServiceInfo> newlist = new ArrayList<ExtendedCAServiceInfo>();
        newlist.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, false));
        cainfo.setExtendedCAServiceInfos(newlist);
        caAdminSession.editCA(admin, cainfo);
        // Did it become deactive?
        cainfo = caSession.getCAInfo(admin, "TEST");
        Collection<ExtendedCAServiceInfo> infos = cainfo.getExtendedCAServiceInfos();
        boolean ok = false;
        for (ExtendedCAServiceInfo info : infos) {
			if (info.getType() == ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE) {
				if (info.getStatus() == ExtendedCAServiceInfo.STATUS_INACTIVE) {
					ok = true;
				}
			}
		}
        assertTrue("extended CA service should have been activated", ok);
    }

}
