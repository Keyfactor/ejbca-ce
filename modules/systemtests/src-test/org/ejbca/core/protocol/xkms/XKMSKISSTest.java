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

package org.ejbca.core.protocol.xkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.xkms.client.XKMSInvoker;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
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
 * To Run this test, there must be a CA with DN
 * "CN=AdminCA1,O=EJBCA Sample,C=SE", and it must have XKMS service enabled.
 * Also you have to enable XKMS in conf/xkms.properties.
 * 
 * 
 * @version $Id$
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XKMSKISSTest {

    private static Logger log = Logger.getLogger(XKMSKISSTest.class);
    private final static AuthenticationToken administrator = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

    static {
        org.apache.xml.security.Init.init();
    }
    
    private final static String HTTPPORT = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST).getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP);

    private static XKMSInvoker xKMSInvoker;

    private ObjectFactory xKMSObjectFactory = new ObjectFactory();
    private org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();

    private static String baseUsername;

    private static String username1 = null;
    private static String username2 = null;
    private static String username3 = null;

    private static String issuerdn;
    private int caid;

    private int userNo;

    private static X509Certificate cert1;
    private static X509Certificate cert2;

    private static String dn1;
    private static String dn2;
    private static String dn3;

    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private RevocationSessionRemote revocationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RevocationSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();

        xKMSInvoker = new XKMSInvoker("http://localhost:" + HTTPPORT + "/ejbca/xkms/xkms", null);
    }
    
    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");    
    
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CAInfo caInfo = null;
        try {
            caInfo = caSession.getCAInfo(administrator, "AdminCA1");
        } catch (CADoesntExistsException e) {
            caInfo = caSession.getCAInfo(administrator, "ManagementCA");
        }
        issuerdn = caInfo.getSubjectDN();
        caid = issuerdn.hashCode();
        
        Random ran = new Random();
        if (baseUsername == null) {
            baseUsername = "xkmstestuser" + (ran.nextInt() % 1000) + "-";
        }
        log.trace("<setUp()");
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        AuthenticationToken administrator = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

        // Setup with two new Certificate profiles.
        CertificateProfile profile1 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile1.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, false);
        profile1.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
        profile1.setKeyUsage(CertificateConstants.NONREPUDIATION, true);

        CertificateProfile profile2 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile2.setKeyUsage(CertificateConstants.DATAENCIPHERMENT, true);

        try {
            certificateProfileSession.addCertificateProfile(administrator, "XKMSTESTSIGN", profile1);
        } catch (CertificateProfileExistsException e) {
            log.info("Certificateprofile XKMSTESTSIGN already exists.");
        }
        try {
            certificateProfileSession.addCertificateProfile(administrator, "XKMSTESTEXCHANDENC", profile2);
        } catch (CertificateProfileExistsException e) {
            log.info("Certificateprofile XKMSTESTSIGN already exists.");
        }

        int profile1Id = certificateProfileSession.getCertificateProfileId("XKMSTESTSIGN");
        int profile2Id = certificateProfileSession.getCertificateProfileId("XKMSTESTEXCHANDENC");

        EndEntityProfile endentityprofile = new EndEntityProfile(true);
        endentityprofile.setValue(EndEntityProfile.AVAILCAS, 0, "" + caid);
        endentityprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER + ";" + profile1Id + ";" + profile2Id);

        try {
            endEntityProfileSession.addEndEntityProfile(administrator, "XKMSTESTPROFILE", endentityprofile);
        } catch (EndEntityProfileExistsException e) {
            log.info("Endentityprofile XKMSTESTPROFILE already exists.");
        }
        int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId("XKMSTESTPROFILE");

        username1 = genUserName();
        String pwd = "foo123";
        EndEntityType type = EndEntityTypes.ENDUSER.toEndEntityType();
        int token = SecConst.TOKEN_SOFT_P12;
        int certificatetypeid = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
        int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
        dn1 = "C=SE, O=AnaTom, CN=" + username1;
        String subjectaltname1 = "RFC822NAME=" + username1 + "@foo.se";
        String email1 = username1 + "@foo.se";
        if (endEntityAccessSession.findUser(administrator, username1) != null) {
            log.info("Error : User already exists in the database.");
        }
        endEntityManagementSession.addUser(administrator, username1, pwd, CertTools.stringToBCDNString(dn1), subjectaltname1, email1, false,
                endEntityProfileId, certificatetypeid, type, token, hardtokenissuerid, caid);
        endEntityManagementSession.setClearTextPassword(administrator, username1, pwd);
        KeyPair keys1 = genKeys();
        cert1 = (X509Certificate) signSession.createCertificate(administrator, username1, "foo123", keys1.getPublic());

        username2 = genUserName();
        dn2 = "C=SE, O=AnaTom, CN=" + username2;
        String subjectaltname2 = "RFC822NAME=" + username2 + "@foo.se,UNIFORMRESOURCEIDENTIFIER=http://www.test.com/" + username2
                + ",IPADDRESS=10.0.0.1,DNSNAME=" + username2 + ".test.com";
        String email2 = username2 + "@foo.se";
        if (endEntityAccessSession.findUser(administrator, username2) != null) {
            log.info("Error : User already exists in the database.");
        }
        endEntityManagementSession.addUser(administrator, username2, pwd, CertTools.stringToBCDNString(dn2), subjectaltname2, email2, false,
                endEntityProfileId, profile1Id, type, token, hardtokenissuerid, caid);
        endEntityManagementSession.setClearTextPassword(administrator, username2, pwd);
        KeyPair keys2 = genKeys();
        cert2 = (X509Certificate) signSession.createCertificate(administrator, username2, "foo123", keys2.getPublic());

        username3 = genUserName();
        dn3 = "C=SE, O=AnaTom, CN=" + username3;
        String subjectaltname3 = "RFC822NAME=" + username3 + "@foo.se";
        String email3 = username3 + "@foo.se";
        if (endEntityAccessSession.findUser(administrator, username3) != null) {
            log.info("Error : User already exists in the database.");
        }
        endEntityManagementSession.addUser(administrator, username3, pwd, CertTools.stringToBCDNString(dn3), subjectaltname3, email3, false,
                endEntityProfileId, profile2Id, type, token, hardtokenissuerid, caid);
        endEntityManagementSession.setClearTextPassword(administrator, username3, pwd);
        KeyPair keys3 = genKeys();
        signSession.createCertificate(administrator, username3, "foo123", keys3.getPublic());
        log.debug("username1: \"" + username1 + "\" dn1: \"" + dn1 + "\"");
        log.debug("username2: \"" + username2 + "\" dn2: \"" + dn2 + "\"");
        log.debug("username3: \"" + username3 + "\" dn3: \"" + dn3 + "\"");
    }

    @Test
    public void test01AbstractType() throws Exception {
        LocateRequestType abstractRequestType = xKMSObjectFactory.createLocateRequestType();
        abstractRequestType.setId("123");
        OpaqueClientDataType opaqueClientDataType = new OpaqueClientDataType();
        opaqueClientDataType.getOpaqueData().add("TEST".getBytes());
        opaqueClientDataType.getOpaqueData().add("TEST2".getBytes());
        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        abstractRequestType.setQueryKeyBinding(queryKeyBindingType);

        abstractRequestType.setOpaqueClientData(opaqueClientDataType);
        LocateResultType abstractResultType = xKMSInvoker.locate(abstractRequestType, null, null);
        assertTrue(abstractResultType.getRequestId().equals("123"));
        assertTrue(!abstractResultType.getId().equals("123"));

        OpaqueClientDataType opaqueClientDataTypeResult = abstractResultType.getOpaqueClientData();
        assertTrue(opaqueClientDataTypeResult.getOpaqueData().size() == 2);
        assertTrue(new String(opaqueClientDataTypeResult.getOpaqueData().get(0)).equals("TEST"));
        assertTrue(new String(opaqueClientDataTypeResult.getOpaqueData().get(1)).equals("TEST2"));

    }

    @Test
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

        LocateResultType abstractResultType = xKMSInvoker.locate(localteRequestType, null, null);
        abstractResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_RECIEVER);
        abstractResultType.getResultMajor().equals(XKMSConstants.RESULTMINOR_TIMEINSTANTNOTSUPPORTED);

    }

    @Test
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

        LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType, null, null);

        assertTrue(locateResultType.getUnverifiedKeyBinding().size() > 0);
    }

    @Test
    public void test04LocateAndUseKeyWith() throws Exception {

        // Locate by URI
        LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("126");
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLS);
        useKeyWithType.setIdentifier("http://www.test.com/" + username2);

        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertEquals("Wrong number of UnverifiedKeyBinding.", 1, locateResultType.getUnverifiedKeyBinding().size());

        // Locate by DNS Name
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("127");
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");

        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
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

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
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

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertEquals("locateResultType.getUnverifiedKeyBinding: ", 1, locateResultType.getUnverifiedKeyBinding().size());

        // Locate by With a more complicated query
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("129");
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn1);

        UseKeyWithType useKeyWithType2 = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType2.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType2.setIdentifier(username2 + ".test.com");

        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType2);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
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
        useKeyWithType2.setIdentifier(username2 + ".test.com");

        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType2);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);

        // Locate by With a more complicated query with one subquery doesn't
        // match
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("129");
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier("CN=nomatch");

        useKeyWithType2 = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType2.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType2.setIdentifier(username2 + ".test.com");

        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType2);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
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

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
    }

    @Test
    public void test05LocateAndReturnWith() throws Exception {
        // Test with returnwith values, first check that certificate is
        // returning
        LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("131");
        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertEquals("Wrong number of UnverifiedKeyBinding.", 1, locateResultType.getUnverifiedKeyBinding().size());
        List<UnverifiedKeyBindingType> numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        Iterator<UnverifiedKeyBindingType> iter = numberOfUnverifiedKeyBindings.iterator();
        KeyInfoType keyInfoType;
        while (iter.hasNext()) {
            UnverifiedKeyBindingType nextKeyBinding = iter.next();
            keyInfoType = nextKeyBinding.getKeyInfo();
            assertTrue(keyInfoType.getContent().size() > 0);
            @SuppressWarnings("unchecked")
            JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
            Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
            while (iter2.hasNext()) {
                @SuppressWarnings("unchecked")
                JAXBElement<byte[]> next = (JAXBElement<byte[]>) iter2.next();
                assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
                byte[] encoded = (byte[]) next.getValue();
                Certificate nextCert = CertTools.getCertfromByteArray(encoded);
                assertTrue(CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(dn2)));
            }

        }
        // Test with return with values, first check that certificate chain is
        // returning
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("132");
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
        numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        iter = numberOfUnverifiedKeyBindings.iterator();
        while (iter.hasNext()) {
            UnverifiedKeyBindingType nextKeyBinding = iter.next();
            keyInfoType = nextKeyBinding.getKeyInfo();
            log.info("keyInfoType: " + keyInfoType.getContent().size());
            /*
             * <?xml version="1.0" ?> <S:Envelope xmlns:S =
             * "http://schemas.xmlsoap.org/soap/envelope/"> <S:Body>
             * <LocateResult xmlns = "http://www.w3.org/2002/03/xkms#" xmlns:ds
             * = "http://www.w3.org/2000/09/xmldsig#" xmlns:xenc =
             * "http://www.w3.org/2001/04/xmlenc#" Id = "_8571741123489298416"
             * RequestId = "132" ResultMajor =
             * "http://www.w3.org/2002/03/xkms#Success" Service =
             * "http://localhost:8080/ejbca/xkms/xkms"> <UnverifiedKeyBinding Id
             * = "_77028bb8eacaafcc"> <ds:KeyInfo> <ds:X509Data>
             * <ds:X509Certificate>
             * MIIDUzCCAjugAwIBAgIISnDjPdYPdp0wDQYJKoZIhvcNAQELBQAwNzERMA8GA1UEAwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDkwMjA5MDM0NzE1WhcNMTkwMjA3MDM0NzE1WjA3MREwDwYDVQQDDAhBZG1pbkNBMTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJIgd
             * +/tqTi3MD1QQsxMZG4uFBK3tp1B8LfFreomTz/
             * xewxii8IpfdQCKxIi7YxzNztLE9v6YWZwrgRJNby8ryDE
             * +mbUWJPu+i66gr6qQy6BYgWNxVMhOKE6d3hmmo5js31sXQ
             * +KY8qz+pM7ukh56xm0GpiNo8t34R7IOZz25KwH
             * +cqrBLDQbkwB/dCQIZmu4/cNxsAJ4lxEsmHkSU6xbRBM5gHLY
             * /mHHuMSptexSeGSC9B7bhMBj31TX4gUmOTz08WA
             * +g7mh4H4QJky0uuHMOJelGTvjdzuiNBImpUendw82llHgbo0zp
             * +wDB9SeHSTC9NnyWbw06O4/
             * CN2vtVZO0UCAwEAAaNjMGEwHQYDVR0OBBYEFMGhHG8TfrEn4kK3ilLiz4zac4tuMA8GA1UdEwEB
             * /
             * wQFMAMBAf8wHwYDVR0jBBgwFoAUwaEcbxN+sSfiQreKUuLPjNpzi24wDgYDVR0PAQH
             * /BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IBAQBX+aHR4T/AeBtoFQdOCdJlvOV9yu/
             * FUTmvogCTG
             * +WDfueVhx7Iap3ZJvPX/h4Q46ax3dy2s0hJMHH6ZA9ve9OANgntIMVP00Ly0Mf
             * +EnTmYkIF34hUk6UoEvTUUUAHJP1m
             * /v8Gm03f+f0QzSpw3AB0ydYTGUHp3cAM6LCE1mgcOMcaxcZBdm
             * +XwyXRUrnuWrKiINhtHjVTm04kgQJIq8lxOrxTVJIBNsgXGjbVkAX0
             * /BXckCLo28Ma70F99kmOz4SBOaqWvl
             * +w8kKwbKgXEp4VXmKSJ4QA6Fugdp20PcUey0EnRnb8CmlGBePOYcM7Lu8Xnqqzd
             * +S3CA9ME5kAYK+j</ds:X509Certificate><ds:X509Certificate>
             * MIIDYjCCAkqgAwIBAgIIdwKLuOrKr8wwDQYJKoZIhvcNAQELBQAwNzERMA8GA1UEAwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDkwMjA5MDU0OTE5WhcNMTEwMjA5MDU0OTE5WjA7MRswGQYDVQQDDBJ4a21zdGVzdHVzZXItOTk1LTIxDzANBgNVBAoMBkFuYVRvbTELMAkGA1UEBhMCU0UwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJdUlNuxmqUHuHRHXaER3DdHvjSxIBjdxoA7oiDnaKJNGLCKf3P2f42I0Musqnu0Fisl7v063b
             * +6DjH5MWeyif2/dZlCtrJS+
             * Gikf6mKyspE139XnoFsYtAq4R5aj01o52cXOGOgslbSdwoPcGKaqTmMR7TLQvMXZwQOc0hBhEtNAgMBAAGjgfEwge4wHQYDVR0OBBYEFDz8G13jKOWsCQ8ywBc7AQw1BR1VMAwGA1UdEwEB
             * /wQCMAAwHwYDVR0jBBgwFoAUwaEcbxN+sSfiQreKUuLPjNpzi24wDgYDVR0PAQH/
             * BAQDAgZAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDBvBgNVHREEaDBmgRl4a21zdGVzdHVzZXItOTk1LTJAZm9vLnNlght4a21zdGVzdHVzZXItOTk1LTIudGVzdC5jb22GJmh0dHA6Ly93d3cudGVzdC5jb20veGttc3Rlc3R1c2VyLTk5NS0yhwQKAAABMA0GCSqGSIb3DQEBCwUAA4IBAQAgDS5TOV7sza9ZD8l6UWxkffBvLF8JuHbVDyDYhukehTWKPn6JyLQOut17PedGykvwBQrP3lBeoHxzd9kVw906IiI
             * +SoIoNGR9HkNdBQksqZu9Stt0F3qbK69qBtZLlA2mwUPxIrI0iLTZ+
             * Qm46zG0Ixsj8ux8UbomH6JYdDsTwuePJFurkYxQmTdx
             * /cGwltp49q+FqoMIL4RjpM1R5WguIKuEvk9E51EA59GOMEbXI374lrlxcvmjSbvv4
             * /
             * SQvqn0CUZgMu+rvWhC1su6FAOI438vS6itGovwZLV/rlqsrbWmsdD3wuj9LGADLX+
             * EP2GFvuWiuLzYzfZ1CppakW1e</ds:X509Certificate> </ds:X509Data>
             * </ds:KeyInfo>
             * <KeyUsage>http://www.w3.org/2002/03/xkms#Signature</KeyUsage>
             * <UseKeyWith Application = "urn:ietf:rfc:2487" Identifier =
             * "xkmstestuser-995-2.test.com"></UseKeyWith> <ValidityInterval
             * NotBefore = "2009-02-09T14:49:19.000+09:00" NotOnOrAfter =
             * "2011-02-09T14:49:19.000+09:00"></ValidityInterval>
             * </UnverifiedKeyBinding> </LocateResult> </S:Body> </S:Envelope>
             */
            // modified by dai 20090209
            // return xml is above, so I think keyInfoType.getContent().size()
            // should be 1 if the xml is correct.
            // assertTrue(keyInfoType.getContent().size() > 1 );
            assertTrue(keyInfoType.getContent().size() > 0);
            @SuppressWarnings("unchecked")
            JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
            assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
            Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
            while (iter2.hasNext()) {
                @SuppressWarnings("unchecked")
                JAXBElement<byte[]> next = (JAXBElement<byte[]>) iter2.next();
                assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
                byte[] encoded = (byte[]) next.getValue();
                Certificate nextCert = CertTools.getCertfromByteArray(encoded);
                assertTrue(CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(dn2))
                        || CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(issuerdn)));
            }

        }

        // Test with returnwith values, require both cert and chain in answer
        // check that just chain is returned
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("133");
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
        numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        iter = numberOfUnverifiedKeyBindings.iterator();
        while (iter.hasNext()) {
            UnverifiedKeyBindingType nextKeyBinding = iter.next();
            keyInfoType = nextKeyBinding.getKeyInfo();
            // modified by dai 20090209 same as above
            // assertTrue(keyInfoType.getContent().size() > 1 );
            assertTrue(keyInfoType.getContent().size() > 0);
            @SuppressWarnings("unchecked")
            JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
            assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
            Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
            while (iter2.hasNext()) {
                @SuppressWarnings("unchecked")
                JAXBElement<byte[]> next = (JAXBElement<byte[]>) iter2.next();
                assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
                byte[] encoded = (byte[]) next.getValue();
                Certificate nextCert = CertTools.getCertfromByteArray(encoded);
                assertTrue(CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(dn2))
                        || CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(issuerdn)));
            }

        }

        // Test with returnwith values, require crl in answer
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("134");
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CRL);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
        numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        iter = numberOfUnverifiedKeyBindings.iterator();
        while (iter.hasNext()) {
            UnverifiedKeyBindingType nextKeyBinding = iter.next();
            keyInfoType = nextKeyBinding.getKeyInfo();
            // modified by dai 20090209 same as above
            // assertTrue(keyInfoType.getContent().size() > 1 );
            assertTrue(keyInfoType.getContent().size() > 0);
            @SuppressWarnings("unchecked")
            JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
            assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 1);
            Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
            while (iter2.hasNext()) {
                @SuppressWarnings("unchecked")
                JAXBElement<byte[]> next = (JAXBElement<byte[]>) iter2.next();
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
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CRL);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
        numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        iter = numberOfUnverifiedKeyBindings.iterator();
        while (iter.hasNext()) {
            UnverifiedKeyBindingType nextKeyBinding = iter.next();
            keyInfoType = nextKeyBinding.getKeyInfo();
            // modified by dai 20090209 same as above
            // assertTrue(keyInfoType.getContent().size() > 1 );
            assertTrue(keyInfoType.getContent().size() > 0);
            @SuppressWarnings("unchecked")
            JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
            assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 3);
            Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
            while (iter2.hasNext()) {
                @SuppressWarnings("unchecked")
                JAXBElement<byte[]> next = (JAXBElement<byte[]>) iter2.next();
                if (next.getName().getLocalPart().equals("X509CRL")) {
                    byte[] encoded = (byte[]) next.getValue();
                    X509CRL nextCRL = CertTools.getCRLfromByteArray(encoded);
                    assertTrue(CertTools.stringToBCDNString(nextCRL.getIssuerDN().toString()).equals(CertTools.stringToBCDNString(issuerdn)));
                }
                if (next.getName().getLocalPart().equals("X509Certificate")) {
                    byte[] encoded = (byte[]) next.getValue();
                    Certificate nextCert = CertTools.getCertfromByteArray(encoded);
                    assertTrue(CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(dn2))
                            || CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(issuerdn)));
                }
            }
        }

        // Test with returnwith values, require keyname in answer
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("135");
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_KEYNAME);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
        numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        iter = numberOfUnverifiedKeyBindings.iterator();
        while (iter.hasNext()) {
            UnverifiedKeyBindingType nextKeyBinding = iter.next();
            keyInfoType = nextKeyBinding.getKeyInfo();
            // modified by dai 20090209 same as above
            // assertTrue(keyInfoType.getContent().size() > 1 );
            assertTrue(keyInfoType.getContent().size() > 0);
            @SuppressWarnings("unchecked")
            JAXBElement<String> jAXBString = (JAXBElement<String>) keyInfoType.getContent().get(0);
            assertTrue(jAXBString.getName().getLocalPart().equals("KeyName"));
            assertTrue(CertTools.stringToBCDNString(jAXBString.getValue()) + " = " + CertTools.stringToBCDNString(dn2), CertTools.stringToBCDNString(
                    jAXBString.getValue()).equals(CertTools.stringToBCDNString(dn2)));
        }

        // Test with returnwith values, require public key in answer
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("135");
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_KEYVALUE);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
        numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        iter = numberOfUnverifiedKeyBindings.iterator();
        while (iter.hasNext()) {
            UnverifiedKeyBindingType nextKeyBinding = iter.next();
            keyInfoType = nextKeyBinding.getKeyInfo();
            assertTrue("" + keyInfoType.getContent().size(), keyInfoType.getContent().size() > 0);
            @SuppressWarnings("unchecked")
            JAXBElement<KeyValueType> jAXBKeyValue = (JAXBElement<KeyValueType>) keyInfoType.getContent().get(0);
            assertTrue(jAXBKeyValue.getName().getLocalPart(), jAXBKeyValue.getName().getLocalPart().equals("KeyValue"));
            assertTrue("" + jAXBKeyValue.getValue().getContent().size(), jAXBKeyValue.getValue().getContent().size() > 0);
            @SuppressWarnings("unchecked")
            JAXBElement<RSAKeyValueType> rSAKeyValueType = (JAXBElement<RSAKeyValueType>) jAXBKeyValue.getValue().getContent().get(0);
            assertTrue(rSAKeyValueType.getName().getLocalPart(), rSAKeyValueType.getName().getLocalPart().equals("RSAKeyValue"));
            BigInteger exp = new BigInteger(rSAKeyValueType.getValue().getExponent());
            BigInteger modulus = new BigInteger(rSAKeyValueType.getValue().getModulus());
            assertTrue(((RSAPublicKey) cert2.getPublicKey()).getModulus().equals(modulus));
            assertTrue(((RSAPublicKey) cert2.getPublicKey()).getPublicExponent().equals(exp));
        }

        // Test with returnwith one invalid values
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("136");
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_RETRIEVALMETHOD);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED));

        // Test with returnwith many invalid values
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("137");
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_RETRIEVALMETHOD);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PGP);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PGPWEB);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_SPKI);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED));

        // Test with many invalid values and one certificate
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("138");
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_RETRIEVALMETHOD);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PGP);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PGPWEB);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_SPKI);
        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);

        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getUnverifiedKeyBinding().size() == 1);
        numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        iter = numberOfUnverifiedKeyBindings.iterator();

        while (iter.hasNext()) {
            UnverifiedKeyBindingType nextKeyBinding = iter.next();
            keyInfoType = nextKeyBinding.getKeyInfo();
            assertTrue(keyInfoType.getContent().size() > 0);
            @SuppressWarnings("unchecked")
            JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);
            Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
            while (iter2.hasNext()) {
                @SuppressWarnings("unchecked")
                JAXBElement<byte[]> next = (JAXBElement<byte[]>) iter2.next();
                assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
                byte[] encoded = (byte[]) next.getValue();
                Certificate nextCert = CertTools.getCertfromByteArray(encoded);
                assertTrue(CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(dn2)));
            }
        }

    }

    @Test
    public void test06LocateAndKeyUsage() throws Exception {
        // request with Signature and expect signature
        LocateRequestType locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("139");
        QueryKeyBindingType queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");

        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getKeyUsage().add(XKMSConstants.KEYUSAGE_SIGNATURE);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertEquals("Wrong number of UnverifiedKeyBinding.", 1, locateResultType.getUnverifiedKeyBinding().size());
        List<UnverifiedKeyBindingType> numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        Iterator<UnverifiedKeyBindingType> iter = numberOfUnverifiedKeyBindings.iterator();
        while (iter.hasNext()) {
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

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        /*
         * <?xml version="1.0" ?> <S:Envelope xmlns:S =
         * "http://schemas.xmlsoap.org/soap/envelope/"> <S:Body> <LocateResult
         * xmlns = "http://www.w3.org/2002/03/xkms#" xmlns:ds =
         * "http://www.w3.org/2000/09/xmldsig#" xmlns:xenc =
         * "http://www.w3.org/2001/04/xmlenc#" Id = "_1669649196518103469"
         * RequestId = "140" ResultMajor =
         * "http://www.w3.org/2002/03/xkms#Success" Service =
         * "http://localhost:8080/ejbca/xkms/xkms"> <UnverifiedKeyBinding Id =
         * "_77cca72c8e066b19"> <ds:KeyInfo> <ds:X509Data>
         * <ds:X509Certificate>MIIDFzCCAf+
         * gAwIBAgIId8ynLI4GaxkwDQYJKoZIhvcNAQELBQAwNzERMA8GA1UEAwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDkwMjA5MDYyNjMyWhcNMTEwMjA5MDYyNjMyWjA7MRswGQYDVQQDDBJ4a21zdGVzdHVzZXItOTAyLTExDzANBgNVBAoMBkFuYVRvbTELMAkGA1UEBhMCU0UwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJJBZdwEN7RCY
         * +46ZnxzrjXOm+h6k/
         * WF6jbt8O5V7YbVr2wL657ivKWBQr8WEEtOheQ9DFFbXq80Adryf8YSRDz4DL5008Fn/
         * LRC5jqCspT6aEhhvSvcvmBEO8YJhR2YhVUHB84p3RD9RvPPRzDsTLXGWScbbjCu1NzdnXX7AGNTAgMBAAGjgaYwgaMwHQYDVR0OBBYEFPYgaKLUO
         * /X7ZC+6Mn3uFzRmTcVwMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUwaEcbxN+
         * sSfiQreKUuLPjNpzi24wDgYDVR0PAQH/
         * BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAkBgNVHREEHTAbgRl4a21zdGVzdHVzZXItOTAyLTFAZm9vLnNlMA0GCSqGSIb3DQEBCwUAA4IBAQAcFUxvDxDcNpkvzp2bdntR9HnaljqlUwPWVQROSr5r0h7iS0
         * /ZJ/
         * kFKLuSdBSoVU1nbuOrtlhNC1zdfE6e86IHbFDK8dk6zJRpYRdsoZcmz9k0F9dX9AmILj9aXS3kiSzyF8L0m02siZZF9dMbpXCgFZCQRGFWLxcNAf6BZTS6c92W7
         * +
         * bPS67vVcGujideTiO8Ud0fU1tyu9BtsqpFItnS9N34sm19MC8pLAzaJjoCNmSXcUl0bswe4d3TkzWKlEjfQeNrRwNP1dI8HJEE7Ddr1j8eE8sW9E
         * /
         * IXQP4QINzF7P6psdtqMlevqx7JFUR6Px73Yn2ASJueScyB9l03Ikj</ds:X509Certificate
         * > </ds:X509Data> </ds:KeyInfo>
         * <KeyUsage>http://www.w3.org/2002/03/xkms#Exchange</KeyUsage>
         * <KeyUsage>http://www.w3.org/2002/03/xkms#Signature</KeyUsage>
         * <UseKeyWith Application = "urn:ietf:rfc:2459" Identifier =
         * "C=SE, O=AnaTom, CN=xkmstestuser-902-1"></UseKeyWith>
         * <ValidityInterval NotBefore = "2009-02-09T15:26:32.000+09:00"
         * NotOnOrAfter = "2011-02-09T15:26:32.000+09:00"></ValidityInterval>
         * </UnverifiedKeyBinding> </LocateResult> </S:Body> </S:Envelope>
         */
        // modified by dai 20090209
        // according to the result xml above, there is no resultminor if the
        // resut is success.
        // so assert for resultminor should not be done if succeed case.
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        // assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));

        // request Exchange or Signature and receive Signature expect Nomatch
        locateRequestType = xKMSObjectFactory.createLocateRequestType();
        locateRequestType.setId("141");
        queryKeyBindingType = xKMSObjectFactory.createQueryKeyBindingType();
        useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_TLSSMTP);
        useKeyWithType.setIdentifier(username2 + ".test.com");

        locateRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
        queryKeyBindingType.getUseKeyWith().add(useKeyWithType);
        queryKeyBindingType.getKeyUsage().add(XKMSConstants.KEYUSAGE_SIGNATURE);
        queryKeyBindingType.getKeyUsage().add(XKMSConstants.KEYUSAGE_EXCHANGE);
        locateRequestType.setQueryKeyBinding(queryKeyBindingType);

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));

        // request Exchange and that response can be used for both exchange and
        // encryption.
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

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertEquals("locateResultType.getUnverifiedKeyBinding: ", 1, locateResultType.getUnverifiedKeyBinding().size());
        numberOfUnverifiedKeyBindings = locateResultType.getUnverifiedKeyBinding();
        iter = numberOfUnverifiedKeyBindings.iterator();
        while (iter.hasNext()) {
            UnverifiedKeyBindingType nextKeyBinding = iter.next();
            // modified by dai 20090224
            /*
             * <?xml version="1.0" ?> <soapenv:Envelope xmlns:soapenv =
             * "http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Body>
             * <LocateRequest xmlns = "http://www.w3.org/2002/03/xkms#" xmlns:ds
             * = "http://www.w3.org/2000/09/xmldsig#" xmlns:xenc =
             * "http://www.w3.org/2001/04/xmlenc#" Id = "142">
             * <RespondWith>http:
             * //www.w3.org/2002/03/xkms#X509Cert</RespondWith>
             * <QueryKeyBinding>
             * <KeyUsage>http://www.w3.org/2002/03/xkms#Encryption</KeyUsage>
             * <KeyUsage>http://www.w3.org/2002/03/xkms#Exchange</KeyUsage>
             * <UseKeyWith Application = "urn:ietf:rfc:2459" Identifier =
             * "C=SE, O=AnaTom, CN=xkmstestuser565-3"></UseKeyWith>
             * </QueryKeyBinding> </LocateRequest> </soapenv:Body>
             * </soapenv:Envelope>
             * 
             * <?xml version="1.0" ?> <S:Envelope xmlns:S =
             * "http://schemas.xmlsoap.org/soap/envelope/"> <S:Body>
             * <LocateResult xmlns = "http://www.w3.org/2002/03/xkms#" xmlns:ds
             * = "http://www.w3.org/2000/09/xmldsig#" xmlns:xenc =
             * "http://www.w3.org/2001/04/xmlenc#" Id = "_6920717384004478797"
             * RequestId = "142" ResultMajor =
             * "http://www.w3.org/2002/03/xkms#Success" Service =
             * "http://localhost:8080/ejbca/xkms/xkms"> <UnverifiedKeyBinding Id
             * = "_60f8a803e9c6aee7"> <ds:KeyInfo> <ds:X509Data>
             * <ds:X509Certificate>MIIDFTCCAf2gAwIBAgIIYPioA+
             * nGrucwDQYJKoZIhvcNAQELBQAwNzERMA8GA1UEAwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDkwMjI0MDYyNDMxWhcNMTEwMjI0MDYyNDMxWjA6MRowGAYDVQQDDBF4a21zdGVzdHVzZXI1NjUtMzEPMA0GA1UECgwGQW5hVG9tMQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAhD0PiOljD
             * +deEE++fshjDbe4kEZXNrVg3xeWy+EMQQ8PtkCiugVzcs4O87z7v/1r+
             * nSQqqVHdZV7beMTsULtSyrj0cCAD4aN
             * +Efurh4J7QzOUmMemNzuC54lBv/9MgEKZsCgFuvbflUIlvwjd/
             * kQP4aM7RbcWkEgiVUNmVXZWf8CAwEAAaOBpTCBojAdBgNVHQ4EFgQUDJ5r9XETomSvPgf1k6NHxTSpnFkwDAYDVR0TAQH
             * /BAIwADAfBgNVHSMEGDAWgBTBoRxvE36xJ+JCt4pS4s+
             * M2nOLbjAOBgNVHQ8BAf8EBAMCBPAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMCMGA1UdEQQcMBqBGHhrbXN0ZXN0dXNlcjU2NS0zQGZvby5zZTANBgkqhkiG9w0BAQsFAAOCAQEAVPQaLAAd
             * /QyIYvbglMtf51ZPZ/2OWbi+
             * nlMqxbpjN3DbdQbTkMnTyp2CpCVDY15XkTthnV7JBBCOm2sTRrSTN
             * +/OgAfacBP830peCKf4fBa
             * +ZAJrU2QYlmORhVjXz2wsJl5Vn+pRBcZSosjTm/VVGwvVai0V25lzrXK8MZEYAJog9uqr
             * /ysW45uN8MgzLa1744rQIrHg5KiJD5exnfUNhUq81CiRKX8JbDV/
             * mDGzwdJoyToG80BTa4buafdDig8qGYlXGgnSpHVkeWtvHoSd
             * /nfJn95n3ftixD6uqVaozC7Z0SKsDrPz2eHN
             * /Mp6qVdDCLtOpD0EM+um3pl4yEm98A==</ds:X509Certificate>
             * </ds:X509Data> </ds:KeyInfo>
             * <KeyUsage>http://www.w3.org/2002/03/xkms#Encryption</KeyUsage>
             * <KeyUsage>http://www.w3.org/2002/03/xkms#Exchange</KeyUsage>
             * <KeyUsage>http://www.w3.org/2002/03/xkms#Signature</KeyUsage>
             * <UseKeyWith Application = "urn:ietf:rfc:2459" Identifier =
             * "C=SE, O=AnaTom, CN=xkmstestuser565-3"></UseKeyWith>
             * <ValidityInterval NotBefore = "2009-02-24T15:24:31.000+09:00"
             * NotOnOrAfter =
             * "2011-02-24T15:24:31.000+09:00"></ValidityInterval>
             * </UnverifiedKeyBinding> </LocateResult> </S:Body> </S:Envelope>
             */
            // The number of KeyUsase is 3. I'm not sure the result is correct
            // or not.
            // assertTrue(nextKeyBinding.getKeyUsage().size() == 2);
            assertTrue(nextKeyBinding.getKeyUsage().size() == 3);
            assertTrue(nextKeyBinding.getKeyUsage().contains(XKMSConstants.KEYUSAGE_ENCRYPTION));
            assertTrue(nextKeyBinding.getKeyUsage().contains(XKMSConstants.KEYUSAGE_EXCHANGE));
        }

    }

    @Test
    public void test07LocateAndResponseLimit() throws Exception {
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

        LocateResultType locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertEquals("Wrong number of UnverifiedKeyBinding.", 3, locateResultType.getUnverifiedKeyBinding().size());

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

        locateResultType = xKMSInvoker.locate(locateRequestType, null, null);
        assertTrue(locateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertTrue(locateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_TOOMANYRESPONSES));
    }

    // unknown testcert
    static byte[] certbytes = Base64.decode(("MIICNzCCAaCgAwIBAgIIIOqiVwJHz+8wDQYJKoZIhvcNAQEFBQAwKzENMAsGA1UE"
            + "AxMEVGVzdDENMAsGA1UEChMEVGVzdDELMAkGA1UEBhMCU0UwHhcNMDQwNTA4MDkx" + "ODMwWhcNMDUwNTA4MDkyODMwWjArMQ0wCwYDVQQDEwRUZXN0MQ0wCwYDVQQKEwRU"
            + "ZXN0MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgbf2" + "Sv34lsY43C8WJjbUd57TNuHJ6p2Es7ojS3D2yxtzQg/A8wL1OfXes344PPNGHkDd"
            + "QPBaaWYQrvLvqpjKwx/vA1835L3I92MsGs+uivq5L5oHfCxEh8Kwb9J2p3xjgeWX" + "YdZM5dBj3zzyu+Jer4iU4oCAnnyG+OlVnPsFt6ECAwEAAaNkMGIwDwYDVR0TAQH/"
            + "BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBQArVZXuGqbb9yhBLbu" + "XfzjSuXfHTAfBgNVHSMEGDAWgBQArVZXuGqbb9yhBLbuXfzjSuXfHTANBgkqhkiG"
            + "9w0BAQUFAAOBgQA1cB6wWzC2rUKBjFAzfkLvDUS3vEMy7ntYMqqQd6+5s1LHCoPw" + "eaR42kMWCxAbdSRgv5ATM0JU3Q9jWbLO54FkJDzq+vw2TaX+Y5T+UL1V0o4TPKxp"
            + "nKuay+xl5aoUcVEs3h3uJDjcpgMAtyusMEyv4d+RFYvWJWFzRTKDueyanw==").getBytes());

    @Test
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

        ValidateResultType validateResultType = xKMSInvoker.validate(validateRequestType, null, null);

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

        validateResultType = xKMSInvoker.validate(validateRequestType, null, null);

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

        validateResultType = xKMSInvoker.validate(validateRequestType, null, null);

        assertTrue(validateResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertTrue(validateResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));

        // Revoke certificate
        AuthenticationToken administrator = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        revocationSession.revokeCertificate(administrator, cert1, new ArrayList<Integer>(), RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, null);
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

        validateResultType = xKMSInvoker.validate(validateRequestType, null, null);

        assertTrue(validateResultType.getKeyBinding().size() > 0);
        assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_VALIDITYINTERVAL));
        assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_ISSUERTRUST));
        assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getValidReason().contains(XKMSConstants.STATUSREASON_SIGNATURE));
        assertTrue(validateResultType.getKeyBinding().get(0).getStatus().getInvalidReason().contains(XKMSConstants.STATUSREASON_REVOCATIONSTATUS));

    }

    @AfterClass
    public static void cleanDatabase() throws AuthorizationDeniedException  {
        AuthenticationToken administrator = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        
        CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

        try {
            endEntityManagementSession.deleteUser(administrator, username1);
        } catch (Exception e) {
            //NOPMD: Ignore
        }
        try {
            endEntityManagementSession.deleteUser(administrator, username2);
        } catch (Exception e) {
            //NOPMD: Ignore
        }
        try {
            endEntityManagementSession.deleteUser(administrator, username3);
        } catch (Exception e) {
            //NOPMD: Ignore
        }
        endEntityProfileSession.removeEndEntityProfile(administrator, "XKMSTESTPROFILE");

        certificateProfileSession.removeCertificateProfile(administrator, "XKMSTESTSIGN");
        certificateProfileSession.removeCertificateProfile(administrator, "XKMSTESTEXCHANDENC");
        certificateProfileSession.removeCertificateProfile(administrator, "XKMSTESTSIGN"+baseUsername+"-");
        certificateProfileSession.removeCertificateProfile(administrator, "XKMSTESTEXCHANDENC"+baseUsername+"-");
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
        log.debug("Generated " + rsaKeys.getPrivate().getAlgorithm() + " keys with length" + ((RSAPrivateKey) rsaKeys.getPrivate()).getModulus().bitLength());

        return rsaKeys;
    } // genKeys
}
