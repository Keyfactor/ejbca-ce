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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.xkms.client.XKMSInvoker;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.KeyValueType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.LocateRequestType;
import org.w3._2002._03.xkms_.LocateResultType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.OpaqueClientDataType;
import org.w3._2002._03.xkms_.QueryKeyBindingType;
import org.w3._2002._03.xkms_.TimeInstantType;
import org.w3._2002._03.xkms_.UnverifiedKeyBindingType;
import org.w3._2002._03.xkms_.UseKeyWithType;
import org.w3._2002._03.xkms_.ValidateRequestType;
import org.w3._2002._03.xkms_.ValidateResultType;

/**
 * 
 * 
 * 
 * @author Philip Vendil 2006 sep 27 
 *
 * @version $Id: TestXKMSKISS.java,v 1.4 2007-02-02 09:37:47 anatom Exp $
 */

public class TestXKMSKISS extends TestCase {
	
	private static Logger log = Logger.getLogger(TestXKMSKISS.class);

	static{
		org.apache.xml.security.Init.init();
	}
	
	private XKMSInvoker xKMSInvoker = new XKMSInvoker("http://localhost:8080/ejbca/xkms/xkms",null);
		
	private ObjectFactory xKMSObjectFactory = new ObjectFactory();
	private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();

	private static String baseUsername;
	private IUserAdminSessionRemote cacheAdmin;
	private IUserAdminSessionHome cacheHome;
	private ISignSessionRemote rsaremote;
	private ICertificateStoreSessionRemote certStore;
	private IRaAdminSessionRemote raAdmin;
	
	private int caid;
	private static String username1 = null;
	private static String username2 = null;
	private static String username3 = null;

	private static String issuerdn = null;
	
	private int userNo;

	private static X509Certificate cert1;
	private static X509Certificate cert2;
	
	private static String dn1;
	private static String dn2;
	private static String dn3;
	
    protected void setUp() throws Exception {
        log.debug(">setUp()");
        CertTools.installBCProvider();

        
        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("UserAdminSession");
                cacheHome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
                
                Object obj = jndiContext.lookup("RSASignSession");
                ISignSessionHome rsahome = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ISignSessionHome.class);
                rsaremote = rsahome.create();
                
                Object obj2 = jndiContext.lookup("CertificateStoreSession");
                ICertificateStoreSessionHome certhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
                certStore = certhome.create();
                
                Object obj3 = jndiContext.lookup("RaAdminSession");
                IRaAdminSessionHome raAdminHome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj3, IRaAdminSessionHome.class);
                raAdmin = raAdminHome.create();
                
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
    	Admin administrator = new Admin(Admin.TYPE_RA_USER);

    	// Setup with two new Certificate profiles.
    	EndUserCertificateProfile profile1 = new EndUserCertificateProfile();
    	profile1.setKeyUsage(CertificateProfile.DIGITALSIGNATURE,false);
    	profile1.setKeyUsage(CertificateProfile.KEYENCIPHERMENT,false);
    	profile1.setKeyUsage(CertificateProfile.NONREPUDIATION,true);
    	
    	EndUserCertificateProfile profile2 = new EndUserCertificateProfile();
    	profile2.setKeyUsage(CertificateProfile.DATAENCIPHERMENT,true);
    	
    	try {
    		certStore.addCertificateProfile(administrator, "XKMSTESTSIGN", profile1);
    	} catch (CertificateProfileExistsException e) {
    		System.out.println("Certificateprofile XKMSTESTSIGN already exists.");
    	}
    	try {
    		certStore.addCertificateProfile(administrator, "XKMSTESTEXCHANDENC", profile2);
    	} catch (CertificateProfileExistsException e) {
    		System.out.println("Certificateprofile XKMSTESTSIGN already exists.");
    	}
    	
    	int profile1Id = certStore.getCertificateProfileId(administrator, "XKMSTESTSIGN");
    	int profile2Id = certStore.getCertificateProfileId(administrator, "XKMSTESTEXCHANDENC");
    	
    	EndEntityProfile endentityprofile = new EndEntityProfile(true);
    	endentityprofile.setValue(EndEntityProfile.AVAILCAS, 0, ""+caid);
    	endentityprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, ""+SecConst.CERTPROFILE_FIXED_ENDUSER +";" + profile1Id + ";" + profile2Id );
    	
    	try {
    		raAdmin.addEndEntityProfile(administrator, "XKMSTESTPROFILE", endentityprofile);
    	} catch (EndEntityProfileExistsException e) {
    		System.out.println("Endentityprofile XKMSTESTPROFILE already exists.");
    	}
        int endEntityProfileId = raAdmin.getEndEntityProfileId(administrator, "XKMSTESTPROFILE");
        
    	
    	username1 = genUserName();
    	String pwd = "foo123";
    	int type = SecConst.USER_ENDUSER;
    	int token = SecConst.TOKEN_SOFT_P12;
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
    	KeyPair keys1 = genKeys();        
    	cert1 = (X509Certificate) rsaremote.createCertificate(administrator, username1, "foo123", keys1.getPublic());

    	username2 = genUserName();
    	dn2 = "C=SE, O=AnaTom, CN=" + username2;
    	String subjectaltname2 = "RFC822NAME=" + username2 + "@foo.se,UNIFORMRESOURCEIDENTIFIER=http://www.test.com/"+username2+",IPADDRESS=10.0.0.1,DNSNAME="+username2+".test.com";
    	String email2 = username2 + "@foo.se";    	
    	if (cacheAdmin.findUser(administrator, username2) != null) {
    		System.out.println("Error : User already exists in the database.");
    	}
    	cacheAdmin.addUser(administrator, username2, pwd, CertTools.stringToBCDNString(dn2), subjectaltname2, email2, false, endEntityProfileId, profile1Id,
    			type, token, hardtokenissuerid, caid);
    	cacheAdmin.setClearTextPassword(administrator, username2, pwd);
    	KeyPair keys2 = genKeys();        
    	cert2 = (X509Certificate) rsaremote.createCertificate(administrator, username2, "foo123", keys2.getPublic());    	

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
    	KeyPair keys3 = genKeys();        
    	 rsaremote.createCertificate(administrator, username3, "foo123", keys3.getPublic());      

    }
    
    public void test01AbstractType() throws Exception {
    	LocateRequestType abstractRequestType = xKMSObjectFactory.createLocateRequestType();
    	abstractRequestType.setId("123");   
    	OpaqueClientDataType opaqueClientDataType = new OpaqueClientDataType();
    	opaqueClientDataType.getOpaqueData().add("TEST".getBytes());
    	opaqueClientDataType.getOpaqueData().add("TEST2".getBytes());
    	QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
    	abstractRequestType.setQueryKeyBinding(queryKeyBindingType);
    	
    	abstractRequestType.setOpaqueClientData(opaqueClientDataType);
    	LocateResultType abstractResultType = xKMSInvoker.locate(abstractRequestType,null,null);
    	assertTrue(abstractResultType.getRequestId().equals("123"));
    	assertTrue(!abstractResultType.getId().equals("123"));
    	
    	OpaqueClientDataType opaqueClientDataTypeResult = abstractResultType.getOpaqueClientData();
    	assertTrue(opaqueClientDataTypeResult.getOpaqueData().size() == 2);
    	assertTrue(new String(opaqueClientDataTypeResult.getOpaqueData().get(0)).equals("TEST"));
    	assertTrue(new String(opaqueClientDataTypeResult.getOpaqueData().get(1)).equals("TEST2"));
    	
    }
    
    public void test02TimeInstantNotSupported() throws Exception {
    	LocateRequestType localteRequestType = xKMSObjectFactory.createLocateRequestType();
    	localteRequestType.setId("124");       	
        	
    	QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
    	TimeInstantType timeInstantType = xKMSObjectFactory.createTimeInstantType();
    	GregorianCalendar caledar = new GregorianCalendar();
    	XMLGregorianCalendar xMLGregorianCalendar = javax.xml.datatype.DatatypeFactory.newInstance().newXMLGregorianCalendar(caledar);
    	xMLGregorianCalendar.normalize();
    	timeInstantType.setTime(xMLGregorianCalendar);
    	queryKeyBindingType.setTimeInstant(timeInstantType);
    	localteRequestType.setQueryKeyBinding(queryKeyBindingType);
    	
    	
    	LocateResultType abstractResultType = xKMSInvoker.locate(localteRequestType,null,null);
    	abstractResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_RECIEVER);
    	abstractResultType.getResultMajor().equals(XKMSConstants.RESULTMINOR_TIMEINSTANTNOTSUPPORTED);
    	
    }
 
    
    public void test03Locate() throws Exception {    	    	
    	
    	// Test simple locate
    	LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("125");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier(username1);
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	
        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);
    	
    	LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType,null,null);
    	
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() > 0);
    }
    
    public void test04LocateAndUseKeyWith() throws Exception {     	
    	
    	// Locate by URI
    	LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("126");    
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLS);
        useKeyWithType.setIdentifier("http://www.test.com/"+username2);
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType,null,null);    	
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	
    	// Locate by DNS Name
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("127");    
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);    	
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	
    	// Locate by IP Name
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("128");    
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_IPSEC);
        useKeyWithType.setIdentifier("10.0.0.1");
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);    	
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() > 0);
    	
    	// Locate by Subject DN
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("129");    
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn1);
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);    	
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    
    	// Locate by With a more complicated query
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("129");    
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn1);
        
        UseKeyWithType useKeyWithType2 = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType2.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType2.setIdentifier(username2+".test.com");
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType2);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
        // Should return the cert of username1 and username2
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 2);
    	
    	// Locate by With a more complicated query but results in only one cert
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("129");    
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn2);
        
        useKeyWithType2 = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType2.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType2.setIdentifier(username2+".test.com");
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType2);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null); 
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	
//    	 Locate by With a more complicated query with one subquery doesn't match
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("129");    
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier("CN=nomatch");
        
        useKeyWithType2 = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType2.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType2.setIdentifier(username2+".test.com");
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType2);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    
    	// Test with certificate
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("130"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        queryKeyBindingType.setKeyInfo(keyInfoType);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    }
    
    public void test05LocateAndReturnWith() throws Exception {    	
    	// Test with returnwith values, first check that certificate is returning
    	LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("131"); 
        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);        
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	List<UnverifiedKeyBindingType> numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	Iterator<UnverifiedKeyBindingType> iter = numberOfUnverifiedKeyBindings.iterator();
    	KeyInfoType keyInfoType;
		while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		keyInfoType = nextKeyBinding.getKeyInfo();
    		assertTrue(keyInfoType.getContent().size() > 0 );								
			JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
			Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
			while(iter2.hasNext()){
				JAXBElement next = (JAXBElement) iter2.next();					
				assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
				byte[] encoded = (byte[]) next.getValue();
				X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
				assertTrue(CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(dn2)));
			}
    		
    	}  
    	// Test with returnwith values, first check that certificate chain is returning
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("132"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);        
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	iter = numberOfUnverifiedKeyBindings.iterator();
    	while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		keyInfoType = nextKeyBinding.getKeyInfo();
    		assertTrue(keyInfoType.getContent().size() > 1 );								
			JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
			assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
			Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
			while(iter2.hasNext()){
				JAXBElement next = (JAXBElement) iter2.next();					
				assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
				byte[] encoded = (byte[]) next.getValue();
				X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
				assertTrue(CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(dn2)) ||
						   CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(issuerdn)));
			}
    		
    	} 
    	
    	// Test with returnwith values, require both cert and chain in answer check that just chain is returned
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("133"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	iter = numberOfUnverifiedKeyBindings.iterator();
    	while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		keyInfoType = nextKeyBinding.getKeyInfo();
    		assertTrue(keyInfoType.getContent().size() > 1 );								
			JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
			assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
			Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
			while(iter2.hasNext()){
				JAXBElement next = (JAXBElement) iter2.next();					
				assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
				byte[] encoded = (byte[]) next.getValue();
				X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
				assertTrue(CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(dn2)) ||
						   CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(issuerdn)));
			}
    		
    	} 
        
    	// Test with returnwith values, require  crl in answer 
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("134"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CRL);        
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	iter = numberOfUnverifiedKeyBindings.iterator();
    	while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		keyInfoType = nextKeyBinding.getKeyInfo();
    		assertTrue(keyInfoType.getContent().size() > 1 );								
			JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
			assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 1);
			Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
			while(iter2.hasNext()){
				JAXBElement next = (JAXBElement) iter2.next();					
				assertTrue(next.getName().getLocalPart().equals("X509CRL"));
				byte[] encoded = (byte[]) next.getValue();
				X509CRL nextCRL = CertTools.getCRLfromByteArray(encoded);
				assertTrue(CertTools.stringToBCDNString(nextCRL.getIssuerDN().toString()).equals(CertTools.stringToBCDNString(issuerdn)));
			}    	
    	} 
    	
    	// Test with returnwith values, require certchain and crl in answer 
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("135"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CRL);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	iter = numberOfUnverifiedKeyBindings.iterator();
    	while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		keyInfoType = nextKeyBinding.getKeyInfo();
    		assertTrue(keyInfoType.getContent().size() > 1 );								
			JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
			assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 3);
			Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
			while(iter2.hasNext()){
				JAXBElement next = (JAXBElement) iter2.next();					
				if(next.getName().getLocalPart().equals("X509CRL")){
				  byte[] encoded = (byte[]) next.getValue();
				  X509CRL nextCRL = CertTools.getCRLfromByteArray(encoded);				
				  assertTrue(CertTools.stringToBCDNString(nextCRL.getIssuerDN().toString()).equals(CertTools.stringToBCDNString(issuerdn)));
				}
				if(next.getName().getLocalPart().equals("X509Certificate")){
					byte[] encoded = (byte[]) next.getValue();
					X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
					assertTrue(CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(dn2)) ||
							   CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(issuerdn)));
				}
			}    	
    	}
    	
    	// Test with returnwith values, require keyname in answer 
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("135"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_KEYNAME);        
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	iter = numberOfUnverifiedKeyBindings.iterator();
    	while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		keyInfoType = nextKeyBinding.getKeyInfo();
    		assertTrue(keyInfoType.getContent().size() > 1 );								
    		JAXBElement<String> jAXBString = (JAXBElement<String>) keyInfoType.getContent().get(0);
    		assertTrue(jAXBString.getName().getLocalPart().equals("KeyName"));
			assertTrue(CertTools.stringToBCDNString(jAXBString.getValue()) + " = " + CertTools.stringToBCDNString(dn2),CertTools.stringToBCDNString(jAXBString.getValue()).equals(CertTools.stringToBCDNString(dn2)));  	
    	}
    	
    	// Test with returnwith values, require public key in answer 
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("135"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_KEYVALUE);        
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	iter = numberOfUnverifiedKeyBindings.iterator();
    	while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		keyInfoType = nextKeyBinding.getKeyInfo();
    		assertTrue("" + keyInfoType.getContent().size(), keyInfoType.getContent().size() > 0 );								
			JAXBElement<KeyValueType> jAXBKeyValue = (JAXBElement<KeyValueType>) keyInfoType.getContent().get(0);	
			assertTrue(jAXBKeyValue.getName().getLocalPart(), jAXBKeyValue.getName().getLocalPart().equals("KeyValue"));
			assertTrue(""+jAXBKeyValue.getValue().getContent().size(),jAXBKeyValue.getValue().getContent().size() > 1);
			JAXBElement<RSAKeyValueType> rSAKeyValueType = (JAXBElement<RSAKeyValueType>) jAXBKeyValue.getValue().getContent().get(0);
			assertTrue(rSAKeyValueType.getName().getLocalPart(),rSAKeyValueType.getName().getLocalPart().equals("RSAKeyValue"));
			BigInteger exp = new BigInteger(rSAKeyValueType.getValue().getExponent());
			BigInteger modulus = new BigInteger(rSAKeyValueType.getValue().getModulus());
			assertTrue(((RSAPublicKey)cert2.getPublicKey()).getModulus().equals(modulus));
			assertTrue(((RSAPublicKey)cert2.getPublicKey()).getPublicExponent().equals(exp));					  	
    	}        
    	
    	// Test with returnwith one invalid values 
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("136"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_RETRIEVALMETHOD);        
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED));

    	// Test with returnwith many invalid values 
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("137"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_RETRIEVALMETHOD);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PGP);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PGPWEB);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_SPKI);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);                         
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED));

         // Test with many invalid values and one certificate
    	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("138"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_RETRIEVALMETHOD);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PGP);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PGPWEB);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_SPKI);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	iter = numberOfUnverifiedKeyBindings.iterator();
    	
		while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		keyInfoType = nextKeyBinding.getKeyInfo();
    		assertTrue(keyInfoType.getContent().size() > 0 );								
			JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
			Iterator iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
			while(iter2.hasNext()){
				JAXBElement next = (JAXBElement) iter2.next();					
				assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
				byte[] encoded = (byte[]) next.getValue();
				X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
				assertTrue(CertTools.stringToBCDNString(nextCert.getSubjectDN().toString()).equals(CertTools.stringToBCDNString(dn2)));
			}    		
    	}
        
        
    }
 
    public void test06LocateAndKeyUsage() throws Exception{
    	// request with Signature and expect signature
       	LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("139"); 
        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);                
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getKeyUsage().add(XKMSConstants.KEYUSAGE_SIGNATURE);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	List<UnverifiedKeyBindingType> numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	Iterator<UnverifiedKeyBindingType> iter = numberOfUnverifiedKeyBindings.iterator();
		while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		assertTrue(nextKeyBinding.getKeyUsage().size() == 1);
    		assertTrue(nextKeyBinding.getKeyUsage().contains(XKMSConstants.KEYUSAGE_SIGNATURE));    		
    	}  
    	    	
    	// request with Signature and receive noMatch
       	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("140"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn1);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);                
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getKeyUsage().add(XKMSConstants.KEYUSAGE_SIGNATURE);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));
        
    	// request Exchange or Signature and receive Signature expect Nomatch
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("141"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2+".test.com");
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);                
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getKeyUsage().add(XKMSConstants.KEYUSAGE_SIGNATURE);
        queryKeyBindingType.getKeyUsage().add(XKMSConstants.KEYUSAGE_EXCHANGE);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));
        
        
        
    	// request Exchange and that response can be used for both exchange and encryption.
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("142"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn3);
        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);                
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getKeyUsage().add(XKMSConstants.KEYUSAGE_ENCRYPTION);
        queryKeyBindingType.getKeyUsage().add(XKMSConstants.KEYUSAGE_EXCHANGE);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));        
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    	numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
    	iter = numberOfUnverifiedKeyBindings.iterator();
		while(iter.hasNext()){
    		UnverifiedKeyBindingType nextKeyBinding = iter.next();
    		assertTrue(nextKeyBinding.getKeyUsage().size() == 2);
    		assertTrue(nextKeyBinding.getKeyUsage().contains(XKMSConstants.KEYUSAGE_ENCRYPTION));
    		assertTrue(nextKeyBinding.getKeyUsage().contains(XKMSConstants.KEYUSAGE_EXCHANGE));
    	}  
				
    }
    
    public void test07LocateAndResponseLimit() throws Exception{
    	// request with 3 and expect 3
       	LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("300"); 
        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier(baseUsername);        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
        locateRequestType.setResponseLimit(new BigInteger("3"));
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 3);
    	
    	// request with 2 and expect 2   	
       	locateRequestType = xKMSObjectFactory.createLocateRequestType();
    	locateRequestType.setId("301"); 
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier(baseUsername);        
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
        locateRequestType.setResponseLimit(new BigInteger("2"));
        
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);   	
    	
        locateResultType = xKMSInvoker.locate(locateRequestType,null,null);  
    	assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
    	assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_TOOMANYRESPONSES));
    }
    
    //unknown testcert
    static byte[] certbytes = Base64.decode(("MIICNzCCAaCgAwIBAgIIIOqiVwJHz+8wDQYJKoZIhvcNAQEFBQAwKzENMAsGA1UE"
            + "AxMEVGVzdDENMAsGA1UEChMEVGVzdDELMAkGA1UEBhMCU0UwHhcNMDQwNTA4MDkx"
            + "ODMwWhcNMDUwNTA4MDkyODMwWjArMQ0wCwYDVQQDEwRUZXN0MQ0wCwYDVQQKEwRU"
            + "ZXN0MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgbf2"
            + "Sv34lsY43C8WJjbUd57TNuHJ6p2Es7ojS3D2yxtzQg/A8wL1OfXes344PPNGHkDd"
            + "QPBaaWYQrvLvqpjKwx/vA1835L3I92MsGs+uivq5L5oHfCxEh8Kwb9J2p3xjgeWX"
            + "YdZM5dBj3zzyu+Jer4iU4oCAnnyG+OlVnPsFt6ECAwEAAaNkMGIwDwYDVR0TAQH/"
            + "BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBQArVZXuGqbb9yhBLbu"
            + "XfzjSuXfHTAfBgNVHSMEGDAWgBQArVZXuGqbb9yhBLbuXfzjSuXfHTANBgkqhkiG"
            + "9w0BAQUFAAOBgQA1cB6wWzC2rUKBjFAzfkLvDUS3vEMy7ntYMqqQd6+5s1LHCoPw"
            + "eaR42kMWCxAbdSRgv5ATM0JU3Q9jWbLO54FkJDzq+vw2TaX+Y5T+UL1V0o4TPKxp"
            + "nKuay+xl5aoUcVEs3h3uJDjcpgMAtyusMEyv4d+RFYvWJWFzRTKDueyanw==").getBytes());
    
    public void test09Validate() throws Exception {    	    	
    	
    	// Test simple validate
    	ValidateRequestType validateRequestType = xKMSObjectFactory.createValidateRequestType();
    	validateRequestType.setId("200");       	
        	
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier(username1);
        
        validateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
    	
        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        validateRequestType.setQueryKeyBinding(queryKeyBindingType);
    	
        ValidateResultType validateResultType = xKMSInvoker.validate(validateRequestType,null,null);
    	
    	assertTrue(validateResultType.getKeyBinding().size() > 0);
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_VALIDITYINTERVAL));
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_ISSUERTRUST));
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_SIGNATURE));
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_REVOCATIONSTATUS));
    	
    	// Test with known certificate.
    	validateRequestType = xKMSObjectFactory.createValidateRequestType();
    	validateRequestType.setId("201");       	
        	
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier(username1);
        
        validateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        queryKeyBindingType.setKeyInfo(keyInfoType);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        validateRequestType.setQueryKeyBinding(queryKeyBindingType);
    	
        validateResultType = xKMSInvoker.validate(validateRequestType,null,null);
    	
        assertTrue(validateResultType.getKeyBinding().size() > 0);
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_VALIDITYINTERVAL));
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_ISSUERTRUST));
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_SIGNATURE));
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_REVOCATIONSTATUS));
    	
        // Test with unknown certificate.
    	validateRequestType = xKMSObjectFactory.createValidateRequestType();
    	validateRequestType.setId("202");       	
        	
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier(username1);
        
        validateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(certbytes));
        keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        queryKeyBindingType.setKeyInfo(keyInfoType);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        validateRequestType.setQueryKeyBinding(queryKeyBindingType);
    	
        validateResultType = xKMSInvoker.validate(validateRequestType,null,null);
    	
        assertTrue(validateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertTrue(validateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));
        
        // Revoke certificate
        Admin administrator = new Admin(Admin.TYPE_RA_USER);
        certStore.revokeCertificate(administrator, cert1, new ArrayList(), RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
    	// Validate with revoked certificate
    	validateRequestType = xKMSObjectFactory.createValidateRequestType();
    	validateRequestType.setId("203");       	
        	
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSHTTP);
        useKeyWithType.setIdentifier(username1);
        
        validateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
    	
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
        queryKeyBindingType.setKeyInfo(keyInfoType);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        validateRequestType.setQueryKeyBinding(queryKeyBindingType);
    	
        validateResultType = xKMSInvoker.validate(validateRequestType,null,null);
    	
        assertTrue(validateResultType.getKeyBinding().size() > 0);
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_VALIDITYINTERVAL));
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_ISSUERTRUST));
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_SIGNATURE));
    	assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getInvalidReason().contains(XKMSConstants.STATUSREASON_REVOCATIONSTATUS));
    	
    }
    
    public void test99CleanDatabase() throws Exception{    	    	
    	Admin administrator = new Admin(Admin.TYPE_RA_USER);
    	cacheAdmin.deleteUser(administrator, username1);
        cacheAdmin.deleteUser(administrator, username2);
    	cacheAdmin.deleteUser(administrator, username3);
    	
    	raAdmin.removeEndEntityProfile(administrator, "XKMSTESTPROFILE");
    	
    	certStore.removeCertificateProfile(administrator, "XKMSTESTSIGN");
    	certStore.removeCertificateProfile(administrator, "XKMSTESTEXCHANDENC");
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
