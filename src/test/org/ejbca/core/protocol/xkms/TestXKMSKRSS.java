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

package org.ejbca.core.protocol.xkms;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Random;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.protocol.xkms.client.XKMSInvoker;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.core.protocol.xkms.common.XKMSNamespacePrefixMapper;
import org.ejbca.core.protocol.xkms.common.XKMSUtil;
import org.ejbca.util.CertTools;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.AuthenticationType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.NotBoundAuthenticationType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.PrototypeKeyBindingType;
import org.w3._2002._03.xkms_.RecoverRequestType;
import org.w3._2002._03.xkms_.RecoverResultType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.RegisterResultType;
import org.w3._2002._03.xkms_.ReissueRequestType;
import org.w3._2002._03.xkms_.ReissueResultType;
import org.w3._2002._03.xkms_.RevokeRequestType;
import org.w3._2002._03.xkms_.RevokeResultType;
import org.w3._2002._03.xkms_.UseKeyWithType;

/**
 * 
 * 
 * 
 * @author Philip Vendil 2006 sep 27 
 *
 * @version $Id: TestXKMSKRSS.java,v 1.2 2007-01-07 00:32:18 herrvendil Exp $
 */

public class TestXKMSKRSS extends TestCase {
	
	private static Logger log = Logger.getLogger(TestXKMSKRSS.class);

	static{
		org.apache.xml.security.Init.init();
	}
	
	private XKMSInvoker xKMSInvoker = new XKMSInvoker("http://localhost:8080/ejbca/xkms/xkms",null);
		
	private ObjectFactory xKMSObjectFactory = new ObjectFactory();
	private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();

	private static String baseUsername;
	private IUserAdminSessionRemote cacheAdmin;
	private IUserAdminSessionHome cacheHome;
	private ICertificateStoreSessionRemote certStore;
	private IRaAdminSessionRemote raAdmin;
	private IKeyRecoverySessionRemote keyAdmin;
	
	private static Admin administrator = new Admin(Admin.TYPE_RA_USER);
	
	private int caid;
	private static String username1 = null;
	private static String username2 = null;
	private static String username3 = null;

	private static String issuerdn = null;
	
	private int userNo;
	
	private static String dn1;
	private static String dn2;
	private static String dn3;
	
	private static KeyPair keys1;
	private static KeyPair keys3;
	
	private static X509Certificate cert1;
	private static X509Certificate cert2;
	
	private static String certprofilename1 = null;
	private static String certprofilename2 = null;
	private static String endentityprofilename = null;
	
	private static GlobalConfiguration orgGlobalConfig = null;
	
	private static int endEntityProfileId;
	
	private static JAXBContext jAXBContext = null;
	private static Marshaller marshaller = null;
	//private static Unmarshaller unmarshaller = null;
	private static DocumentBuilderFactory dbf = null;
	
	static{    	
		try {
			CertTools.installBCProvider();
			org.apache.xml.security.Init.init();

			jAXBContext = JAXBContext.newInstance("org.w3._2002._03.xkms_:org.w3._2001._04.xmlenc_:org.w3._2000._09.xmldsig_");    		
			marshaller = jAXBContext.createMarshaller();
			try {
				marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper",new XKMSNamespacePrefixMapper());
			} catch( PropertyException e ) {
				log.error("Error registering namespace mapper property",e);
			}
			dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			//unmarshaller = jAXBContext.createUnmarshaller();

		} catch (JAXBException e) {
			log.error("Error initializing RequestAbstractTypeResponseGenerator",e);
		}

	}
	
    protected void setUp() throws Exception {
        log.debug(">setUp()");
        CertTools.installBCProvider();

        
        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("UserAdminSession");
                cacheHome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
                
                
                Object obj2 = jndiContext.lookup("CertificateStoreSession");
                ICertificateStoreSessionHome certhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
                certStore = certhome.create();
                
                Object obj3 = jndiContext.lookup("RaAdminSession");
                IRaAdminSessionHome raAdminHome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj3, IRaAdminSessionHome.class);
                raAdmin = raAdminHome.create();
                
                Object obj4 = jndiContext.lookup("KeyRecoverySession");
                IKeyRecoverySessionHome keyAdminHome = (IKeyRecoverySessionHome) javax.rmi.PortableRemoteObject.narrow(obj4, IKeyRecoverySessionHome.class);
                keyAdmin = keyAdminHome.create();
                
                issuerdn = "CN=AdminCA1,O=EJBCA Sample,C=SE"; 
                caid = issuerdn.hashCode();
                
            }

            cacheAdmin = cacheHome.create();
        }      

        
        Random ran = new Random();
        if(baseUsername == null){
          baseUsername = "xkmstestuser" + (ran.nextInt() % 1000) + "-";
        }
        
        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }
    
    public void test00SetupDatabase() throws Exception{
    	

    	certprofilename1 = "XKMSTESTSIGN" + baseUsername;
    	certprofilename2 = "XKMSTESTEXCHANDENC" + baseUsername;
    	endentityprofilename = "XKMSTESTPROFILE" + baseUsername;
    	
    	orgGlobalConfig = raAdmin.loadGlobalConfiguration(administrator);
    	
    	GlobalConfiguration newGlobalConfig = raAdmin.loadGlobalConfiguration(administrator);
    	newGlobalConfig.setEnableKeyRecovery(true);
    	raAdmin.saveGlobalConfiguration(administrator, newGlobalConfig);
    	
    	
    	// Setup with two new Certificate profiles.
    	EndUserCertificateProfile profile1 = new EndUserCertificateProfile();
    	profile1.setKeyUsage(CertificateProfile.DIGITALSIGNATURE,false);
    	profile1.setKeyUsage(CertificateProfile.KEYENCIPHERMENT,false);
    	profile1.setKeyUsage(CertificateProfile.NONREPUDIATION,true);
    	
    	EndUserCertificateProfile profile2 = new EndUserCertificateProfile();
    	profile2.setKeyUsage(CertificateProfile.DATAENCIPHERMENT,true);
    	
    	certStore.addCertificateProfile(administrator, certprofilename1, profile1);
    	certStore.addCertificateProfile(administrator, certprofilename2, profile2);
    	
    	int profile1Id = certStore.getCertificateProfileId(administrator, certprofilename1);
    	int profile2Id = certStore.getCertificateProfileId(administrator, certprofilename2);
    	
    	EndEntityProfile endentityprofile = new EndEntityProfile(true);
    	
    	endentityprofile.setValue(EndEntityProfile.AVAILCAS, 0, ""+caid);
    	endentityprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, ""+SecConst.CERTPROFILE_FIXED_ENDUSER +";" + profile1Id + ";" + profile2Id );
    	
    	endentityprofile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
    	
    	raAdmin.addEndEntityProfile(administrator, endentityprofilename, endentityprofile);
        endEntityProfileId = raAdmin.getEndEntityProfileId(administrator, endentityprofilename);
        
    	
    	username1 = genUserName();
    	String pwd = "foo123";
    	int type = SecConst.USER_ENDUSER ;
    	int token = SecConst.TOKEN_SOFT_BROWSERGEN;
    	int certificatetypeid = SecConst.CERTPROFILE_FIXED_ENDUSER;
    	int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
    	dn1 = "C=SE, O=AnaTom, CN=" + username1;
    	String subjectaltname1 = "RFC822NAME=" + username1 + "@foo.se";
    	String email1 = username1 + "@foo.se";
    	if (cacheAdmin.findUser(administrator, username1) != null) {
    		System.out.println("Error : User already exists in the database.");
    	}
    	cacheAdmin.addUser(administrator, username1, pwd, CertTools.stringToBCDNString(dn1), subjectaltname1, email1, false, endEntityProfileId, certificatetypeid,
    			type, token, hardtokenissuerid, caid);
    	cacheAdmin.setClearTextPassword(administrator, username1, pwd);
 
    	username2 = genUserName();
    	dn2 = "C=SE, O=AnaTom, CN=" + username2;
    	type = SecConst.USER_ENDUSER | SecConst.USER_KEYRECOVERABLE;
    	token = SecConst.TOKEN_SOFT_P12;
    	String subjectaltname2 = "RFC822NAME=" + username2 + "@foo.se,UNIFORMRESOURCEIDENTIFIER=http://www.test.com/"+username2+",IPADDRESS=10.0.0.1,DNSNAME="+username2+".test.com";
    	String email2 = username2 + "@foo.se";    	
    	if (cacheAdmin.findUser(administrator, username2) != null) {
    		System.out.println("Error : User already exists in the database.");
    	}
    	cacheAdmin.addUser(administrator, username2, pwd, CertTools.stringToBCDNString(dn2), subjectaltname2, email2, false, endEntityProfileId, profile1Id,
    			type, token, hardtokenissuerid, caid);
    	cacheAdmin.setClearTextPassword(administrator, username2, pwd);

    	username3 = genUserName();
    	dn3 = "C=SE, O=AnaTom, CN=" + username3;
    	String subjectaltname3 = "RFC822NAME=" + username3 + "@foo.se";
    	String email3 = username3 + "@foo.se";
    	if (cacheAdmin.findUser(administrator, username3) != null) {
    		System.out.println("Error : User already exists in the database.");
    	}
    	cacheAdmin.addUser(administrator, username3, pwd, CertTools.stringToBCDNString(dn3), subjectaltname3, email3, false, endEntityProfileId, profile2Id,
    			type, token, hardtokenissuerid, caid);
    	cacheAdmin.setClearTextPassword(administrator, username3, pwd);

    }
    
    public void test01SimpleRegistration() throws Exception{
    	
    	keys1 = genKeys();
     	RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
    	registerRequestType.setId("600");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn1);
        
        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys1.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys1.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);                                
                
        
        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeIdentifier", true,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        byte[] second = XKMSUtil.getSecretKeyFromPassphrase(new String(first), false,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS2).getEncoded();
        prototypeKeyBindingType.setRevocationCodeIdentifier(second);
        
		RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", keys1.getPrivate(), prototypeKeyBindingType.getId());
		
		assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));

		assertTrue(registerResultType.getKeyBinding().size() == 1);
		KeyBindingType keyBindingType = registerResultType.getKeyBinding().get(0);
		assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);
		
		JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
		assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
		Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
		while(iter2.hasNext()){
			JAXBElement next = (JAXBElement) iter2.next();					
			assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
			byte[] encoded = (byte[]) next.getValue();
			X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
			
			assertTrue(CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(dn1)) ||
					   CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(issuerdn)));
			if(CertTools.getSubjectDN(nextCert).equals(CertTools.stringToBCDNString(dn1))){
				assertTrue(Arrays.equals(keys1.getPublic().getEncoded(), nextCert.getPublicKey().getEncoded()));
                cert1 = nextCert;				
			}
		}	
    }
    
    public void test02ServerGenRegistration() throws Exception{
     	RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
    	registerRequestType.setId("601");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn2);
        
        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
      
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
      
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);                

        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeId‰ÂˆË", true,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        byte[] second = XKMSUtil.getSecretKeyFromPassphrase(new String(first), false,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS2).getEncoded();
        prototypeKeyBindingType.setRevocationCodeIdentifier(second);
        
        
		RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", null, prototypeKeyBindingType.getId());
		
		assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));

		assertTrue(registerResultType.getKeyBinding().size() == 1);
		KeyBindingType keyBindingType = registerResultType.getKeyBinding().get(0);
		assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);
		
		JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
		assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 1);
		Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
		
		while(iter2.hasNext()){
			JAXBElement next = (JAXBElement) iter2.next();					
			assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
			byte[] encoded = (byte[]) next.getValue();
			X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
			
			assertTrue(CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(dn2)));
			if(CertTools.getSubjectDN(nextCert).equals(CertTools.stringToBCDNString(dn2))){
				cert2 = nextCert;
				
			}
		}	
		
		assertTrue(registerResultType.getPrivateKey() != null);
		PrivateKey privateKey = XKMSUtil.getPrivateKeyFromEncryptedXML(registerResultType.getPrivateKey(), "foo123");
		
		X509Certificate testCert = CertTools.genSelfCert("CN=sdf", 12, null, privateKey, cert2.getPublicKey(), "SHA1WithRSA", false);
		testCert.verify(cert2.getPublicKey());
		
    }
    
    public void test03RegisterWithWrongDN() throws Exception{
    	keys3 = genKeys();
     	RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
    	registerRequestType.setId("602");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier("CN=wrong");
        
        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys3.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys3.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);                                
        
		RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", keys3.getPrivate(), prototypeKeyBindingType.getId());
		
		assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));

    }
    
    public void test04RegisterWithWrongStatus() throws Exception{
    	KeyPair keys = genKeys();
     	RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
    	registerRequestType.setId("603");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn1);
        
        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);                                
        
		RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", keys.getPrivate(), prototypeKeyBindingType.getId());
		
		assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));

		
    }
    
    public void test05RegisterWithWrongPassword() throws Exception{
    	KeyPair keys = genKeys();
     	RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
    	registerRequestType.setId("604");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn3);
        
        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);                                
        
		RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo124", keys.getPrivate(), prototypeKeyBindingType.getId());
		
		assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));

		
    }
    
    public void test06RegisterWithNoPOP() throws Exception{
    	KeyPair keys = genKeys();
     	RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
    	registerRequestType.setId("605");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn3);
        
        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);                                
        
		RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", null, prototypeKeyBindingType.getId());
		
		assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_POPREQUIRED));

		
    }
    
    public void test07RegisterWithBasicAuthentication() throws Exception{
    	KeyPair keys = genKeys();
     	RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
    	registerRequestType.setId("606");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn3);
        
        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("foo123".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        registerRequestType.setAuthentication(authenticationType);
        
		RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, null, keys.getPrivate(), prototypeKeyBindingType.getId());
		
		assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));

		assertTrue(registerResultType.getKeyBinding().size() == 1);
		KeyBindingType keyBindingType = registerResultType.getKeyBinding().get(0);
		assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);
		
    }
    
    public void test08SimpleReissue() throws Exception{
    	cacheAdmin.setUserStatus(administrator, username1, 10);
    	cacheAdmin.setClearTextPassword(administrator, username1, "ReissuePassword");
     	ReissueRequestType reissueRequestType = xKMSObjectFactory.createReissueRequestType();
     	reissueRequestType.setId("607");       	
        	               
     	reissueRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	     
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123122");
        reissueRequestType.setReissueKeyBinding(keyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("ReissuePassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        reissueRequestType.setAuthentication(authenticationType);
        
		ReissueResultType reissueResultType = xKMSInvoker.reissue(reissueRequestType, null, null, null, keys1.getPrivate(), keyBindingType.getId());
		
		assertTrue(reissueResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
		assertTrue(reissueResultType.getResultMinor() == null);

		assertTrue(reissueResultType.getKeyBinding().size() == 1);
		keyBindingType = reissueResultType.getKeyBinding().get(0);
		assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);
		
		JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
		assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
		Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
		while(iter2.hasNext()){
			JAXBElement next = (JAXBElement) iter2.next();					
			assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
			byte[] encoded = (byte[]) next.getValue();
			X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
			
			assertTrue(CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(dn1)) ||
					   CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(issuerdn)));
			if(CertTools.getSubjectDN(nextCert).equals(CertTools.stringToBCDNString(dn1))){
				assertTrue(Arrays.equals(keys1.getPublic().getEncoded(), nextCert.getPublicKey().getEncoded()));
				assertFalse(cert1.getSerialNumber().equals(nextCert.getSerialNumber()));                				
			}
		}
    }
    
    public void test09ReissueWrongPassword() throws Exception{
    	cacheAdmin.setUserStatus(administrator, username1, 10);
    	cacheAdmin.setClearTextPassword(administrator, username1, "ReissuePassword");
     	ReissueRequestType reissueRequestType = xKMSObjectFactory.createReissueRequestType();
     	reissueRequestType.setId("608");       	
        	               
     	reissueRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	     
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123122");
        reissueRequestType.setReissueKeyBinding(keyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("Wrong".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        reissueRequestType.setAuthentication(authenticationType);
        
		ReissueResultType reissueResultType = xKMSInvoker.reissue(reissueRequestType, null, null, null, keys1.getPrivate(), keyBindingType.getId());
		
		assertTrue(reissueResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(reissueResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));

		
    }
    
    public void test10ReissueWrongStatus() throws Exception{
    	cacheAdmin.setUserStatus(administrator, username1, 40);
    	cacheAdmin.setClearTextPassword(administrator, username1, "ReissuePassword");
     	ReissueRequestType reissueRequestType = xKMSObjectFactory.createReissueRequestType();
     	reissueRequestType.setId("609");       	
        	               
     	reissueRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	     
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123122");
        reissueRequestType.setReissueKeyBinding(keyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("ReissuePassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        reissueRequestType.setAuthentication(authenticationType);
        
		ReissueResultType reissueResultType = xKMSInvoker.reissue(reissueRequestType, null, null, null, keys1.getPrivate(), keyBindingType.getId());
		
		assertTrue(reissueResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(reissueResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));		
    }
    
    public void test11ReissueWrongCert() throws Exception{
    	
    	cacheAdmin.setUserStatus(administrator, username1, 10);
    	cacheAdmin.setClearTextPassword(administrator, username1, "ReissuePassword");
     	ReissueRequestType reissueRequestType = xKMSObjectFactory.createReissueRequestType();
     	reissueRequestType.setId("610");       	
        	               
     	reissueRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	     
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(Constants.getUserCert().getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123122");
        reissueRequestType.setReissueKeyBinding(keyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("ReissuePassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        reissueRequestType.setAuthentication(authenticationType);
        
		ReissueResultType reissueResultType = xKMSInvoker.reissue(reissueRequestType, null, null, null, keys1.getPrivate(), keyBindingType.getId());
		
		assertTrue(reissueResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(reissueResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));		
    }
    
    public void test12SimpleRecover() throws Exception{
    	keyAdmin.markAsRecoverable(administrator, cert2, endEntityProfileId);    	
    	cacheAdmin.setClearTextPassword(administrator, username2, "RerecoverPassword");
     	RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
     	recoverRequestType.setId("700");       	
        	               
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);
    	     
     	
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("RerecoverPassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);
        
		RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null,  keyBindingType.getId());
		
		assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
		assertTrue(recoverResultType.getResultMinor() == null);	
		
		assertTrue(recoverResultType.getKeyBinding().size() == 1);
		keyBindingType = recoverResultType.getKeyBinding().get(0);
		assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);
		
		JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
		assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
		Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
		
		while(iter2.hasNext()){
			JAXBElement next = (JAXBElement) iter2.next();					
			assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
			byte[] encoded = (byte[]) next.getValue();
			X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
			
			if(CertTools.getSubjectDN(nextCert).equals(CertTools.stringToBCDNString(dn2))){
				cert2 = nextCert;
				
			}
		}	
		
		assertTrue(recoverResultType.getPrivateKey() != null);
		PrivateKey privateKey = XKMSUtil.getPrivateKeyFromEncryptedXML(recoverResultType.getPrivateKey(), "RerecoverPassword");
		
		X509Certificate testCert = CertTools.genSelfCert("CN=sdf", 12, null, privateKey, cert2.getPublicKey(), "SHA1WithRSA", false);
		testCert.verify(cert2.getPublicKey());
		
		
    }
    
    public void test13RecoverWrongPassword() throws Exception{
    	keyAdmin.markAsRecoverable(administrator, cert2, endEntityProfileId);    	
    	cacheAdmin.setClearTextPassword(administrator, username2, "RerecoverPassword");
     	RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
     	recoverRequestType.setId("701");       	
        	               
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);    	     
     	
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("Wrong".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);
        
		RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null,  keyBindingType.getId());
		
		assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));	
	
    }
  
    public void test14RecoverWrongStatus() throws Exception{
    	cacheAdmin.setUserStatus(administrator, username2, 10);    	    	
    	cacheAdmin.setClearTextPassword(administrator, username2, "RerecoverPassword");
     	RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
     	recoverRequestType.setId("702");       	
        	               
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);
    	     
     	
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("RerecoverPassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);
        
		RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null,  keyBindingType.getId());
		
		assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));	

    }
    
    public void test15RecoverWrongCert() throws Exception{
    	cacheAdmin.setUserStatus(administrator, username2, UserDataConstants.STATUS_KEYRECOVERY);    	    	
    	cacheAdmin.setClearTextPassword(administrator, username2, "RerecoverPassword");
     	RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
     	recoverRequestType.setId("703");       	
        	               
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);
    	     
     	
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(Constants.getUserCert().getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("RerecoverPassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);
        
		RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null,  keyBindingType.getId());
		
		assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));	

    }
    
    public void test16CertNotMarked() throws Exception{
    	keyAdmin.unmarkUser(administrator, username2);
    	cacheAdmin.setUserStatus(administrator, username2, 40);    	    	
    	cacheAdmin.setClearTextPassword(administrator, username2, "RerecoverPassword");
     	RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
     	recoverRequestType.setId("704");       	
        	               
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
     	recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);
    	     
     	
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);                                
        
        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("RerecoverPassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);
        
		RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null,  keyBindingType.getId());
		
		assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));	

    }
    
    public void test17SimpleRevoke() throws Exception{
     	RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
     	revokeRequestType.setId("800");       	
        	               

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        revokeRequestType.setRevokeKeyBinding(keyBindingType);
        
        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeIdentifier", true,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        revokeRequestType.setRevocationCode(first);
        
        
		RevokeResultType revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null,  keyBindingType.getId());
		
		assertTrue(revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
		assertTrue(revokeResultType.getResultMinor() == null );	

    }
    
    public void test18RevokeWrongPassword() throws Exception{
     	RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
     	revokeRequestType.setId("801");       	
        	               

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        revokeRequestType.setRevokeKeyBinding(keyBindingType);
        
        revokeRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("Wrong", true,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        revokeRequestType.setRevocationCode(first);        
        
        
		RevokeResultType revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null,  keyBindingType.getId());
		
		assertTrue(revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));	
    }
    
    public void test19RevokeWithResult() throws Exception{
     	RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
     	revokeRequestType.setId("802");       	
        	               

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        revokeRequestType.setRevokeKeyBinding(keyBindingType);
        
        revokeRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
        

        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeId‰ÂˆË", true,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        revokeRequestType.setRevocationCode(first);
        
		RevokeResultType revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null,  keyBindingType.getId());
		
		assertTrue(revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
		assertTrue(revokeResultType.getResultMinor() == null );	
		
		assertTrue(revokeResultType.getKeyBinding().size() == 1);
		keyBindingType = revokeResultType.getKeyBinding().get(0);
		assertTrue(keyBindingType.getStatus().getValidReason().size() == 3);
		assertTrue(keyBindingType.getStatus().getInvalidReason().size() == 1);
		
		JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
		assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 1);
		Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
		
		while(iter2.hasNext()){
			JAXBElement next = (JAXBElement) iter2.next();					
			assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
			byte[] encoded = (byte[]) next.getValue();
			X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
			
			assertTrue(CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(dn2)));
			
		}	
    }
    
    public void test20RevokeAlreadyRevoked() throws Exception{
     	RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
     	revokeRequestType.setId("804");       	
        	               

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        
        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();                
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        revokeRequestType.setRevokeKeyBinding(keyBindingType);
        
        revokeRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);                        
        
        
        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeId‰ÂˆË", true,20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        revokeRequestType.setRevocationCode(first);
        
		RevokeResultType revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null,  keyBindingType.getId());
		
		assertTrue(revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
		assertTrue(revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));	
    }
     
    public void test99CleanDatabase() throws Exception{    	    	
    	Admin administrator = new Admin(Admin.TYPE_RA_USER);
    	cacheAdmin.deleteUser(administrator, username1);
        cacheAdmin.deleteUser(administrator, username2);
    	cacheAdmin.deleteUser(administrator, username3);
    	
    	raAdmin.removeEndEntityProfile(administrator, endentityprofilename);
    	
    	certStore.removeCertificateProfile(administrator, certprofilename1);
    	certStore.removeCertificateProfile(administrator, certprofilename2);
    	
    	raAdmin.saveGlobalConfiguration(administrator, orgGlobalConfig);
    }
    
    
    private Context getInitialContext() throws NamingException {
        log.debug(">getInitialContext");

        Context ctx = new javax.naming.InitialContext();
        log.debug("<getInitialContext");

        return ctx;
    }
    
    private String genUserName() throws Exception {
        // Gen new user
        userNo++;

        return baseUsername + userNo;
    } // genRandomUserName
    
    private static KeyPair genKeys() throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(1024);
        log.debug("Generating keys, please wait...");
        KeyPair rsaKeys = keygen.generateKeyPair();
        log.debug("Generated " + rsaKeys.getPrivate().getAlgorithm() + " keys with length" +
                ((RSAPrivateKey) rsaKeys.getPrivate()).getModulus().bitLength());

        return rsaKeys;
    } // genKeys
}
