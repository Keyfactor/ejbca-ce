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

package org.ejbca.core.model.ca.caadmin;

import java.security.cert.CertStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;


/**
 * Tests the CertTools class.
 *
 * @version $Id: TestCmsCAService.java,v 1.2 2007-04-13 06:23:08 herrvendil Exp $
 */
public class TestCmsCAService extends TestCase {
	private static Logger log = Logger.getLogger(TestCmsCAService.class);

	private byte[] doc = "foo123".getBytes();

	private static ISignSessionRemote remote;
	private static ICAAdminSessionRemote casession;
	private static int rsacaid = 0;
	private Admin admin;

	/**
	 * Creates a new TestCertTools object.
	 *
	 * @param name DOCUMENT ME!
	 */
	public TestCmsCAService(String name) throws Exception {
		super(name);
		// Install BouncyCastle provider
		CertTools.installBCProvider();
		Context ctx = getInitialContext();
		Object obj = ctx.lookup(ISignSessionHome.JNDI_NAME);
		ISignSessionHome home = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ISignSessionHome.class);
		remote = home.create();

		admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);

		obj = ctx.lookup(ICAAdminSessionHome.JNDI_NAME);
		ICAAdminSessionHome cahome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICAAdminSessionHome.class);
		casession = cahome.create();
		CAInfo inforsa = casession.getCAInfo(admin, "TEST");
		rsacaid = inforsa.getCAId();
		if (rsacaid == 0){
			assertTrue("No active RSA CA! Must have at least one active CA to run tests!", false);
		}

	}

	protected void setUp() throws Exception {
		log.debug(">setUp()");
		CertTools.installBCProvider();
		log.debug("<setUp()");
	}

	protected void tearDown() throws Exception {
	}

	private Context getInitialContext() throws NamingException {
		log.debug(">getInitialContext");

		Context ctx = new javax.naming.InitialContext();
		log.debug("<getInitialContext");

		return ctx;
	}

	/**
	 */
	public void test01CmsCAServiceNotActive() throws Exception {
		CmsCAServiceRequest request = new CmsCAServiceRequest(doc, CmsCAServiceRequest.MODE_SIGN);
		
		// First try a request when the service is not active
		boolean active = true;
		try {
			remote.extendedService(admin, rsacaid, request);
		} catch (ExtendedCAServiceNotActiveException e) {
			active = false;
		}
		// By default the CA service is not active
		assertTrue(!active);
        
	}
	
	/**
	 */
	public void test02ActivateCmsCAService() throws Exception {
		// Activate the CA service in the CA
		CAInfo cainfo = casession.getCAInfo(admin, "TEST");
		ArrayList newlist = new ArrayList();
		newlist.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE, false));
		cainfo.setExtendedCAServiceInfos(newlist);
		casession.editCA(admin, cainfo);
	}
	
	/**
	 */
	public void test03CmsCAServiceActive() throws Exception {
		CmsCAServiceRequest request = new CmsCAServiceRequest(doc, CmsCAServiceRequest.MODE_SIGN);
		CmsCAServiceResponse resp = null;
		// Try the request again
		boolean active = true;
		try {
			resp = (CmsCAServiceResponse)remote.extendedService(admin, rsacaid, request);
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
        Collection signers = infoStore.getSigners();
        Iterator iter = signers.iterator();
//        FileOutputStream fos = new FileOutputStream("/home/tomas/p7.der");
//        fos.write(doc);
//        fos.close();
        if (iter.hasNext()) {
        	SignerInformation si = (SignerInformation)iter.next();
        	assertNotNull(si);
        	//log.info("Digest alg is: "+si.getDigestAlgOID());
        	assertEquals(CMSSignedGenerator.DIGEST_SHA1, si.getDigestAlgOID());
        	SignerId sid = si.getSID();
        	//log.info(sid.toString());
        	X500Principal issuer = sid.getIssuer();
        	assertNotNull(issuer);
        	assertEquals("CN=TEST", issuer.getName());        	
        }        	
        CertStore store = csd.getCertificatesAndCRLs("Collection", "BC");
        Collection certs = store.getCertificates(null);
        assertEquals(2, certs.size());
        
        CMSProcessable cp = csd.getSignedContent();
        Object o = cp.getContent();
        byte[] ob = (byte[])o;
        assertEquals(new String(doc), new String(ob));
	}
	
	/**
	 */
	public void test03CmsCAEncryptDecrypt() throws Exception {
		CmsCAServiceRequest request = new CmsCAServiceRequest(doc, CmsCAServiceRequest.MODE_ENCRYPT);
		CmsCAServiceResponse resp = null;
		// Try the request again
		boolean active = true;
		try {
			resp = (CmsCAServiceResponse)remote.extendedService(admin, rsacaid, request);
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
			resp = (CmsCAServiceResponse)remote.extendedService(admin, rsacaid, request);
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

	/**
	 */
	public void test04DeActivateCmsCAService() throws Exception {
		// Activate the CA service in the CA
		CAInfo cainfo = casession.getCAInfo(admin, "TEST");
		ArrayList newlist = new ArrayList();
		newlist.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, false));
		cainfo.setExtendedCAServiceInfos(newlist);
		casession.editCA(admin, cainfo);
	}

}
