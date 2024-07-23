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
package org.ejbca.core.protocol.ssh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.ssh.SshCertificateType;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.junit.Before;
import org.junit.Test;

/**
 *  Mainly tests conversion between SshRequestMessage and EndEntityInformation,
 *  1. for persistence in DB during user enrollment
 *  2. from persisted data during certificate issuance
 *  
 */
public class SshRequestMessageUnitTest {
    
    private static CertificateProfile certProfile;
    
    @Before
    public void init() {
        certProfile = new CertificateProfile();
        certProfile.setType(CertificateConstants.CERTTYPE_SSH);
        certProfile.setSshCertificateType(SshCertificateType.USER);
    }
    
    // DN
    // any keyId
    @Test
    public void testAnyKeyId() {
        String keyId = "someKeyId";
        SshRequestMessage req = new SshRequestMessage("".getBytes(), keyId, null, null, null, null);
        
        EndEntityInformation userData = new EndEntityInformation();
        req.populateEndEntityData(userData, certProfile);
        
        assertEquals("SubjectDn mismatch", "CN="+keyId, userData.getDN());
        
        userData.setDN("CN="+keyId);
        req = new SshRequestMessage("CN="+keyId, "", new ExtendedInformation());
        assertEquals("keyId mismatch", keyId, req.getKeyId());
    }
    
    // blank KeyId
    @Test
    public void testBlankKeyId() {
        String keyId = "";
        SshRequestMessage req = new SshRequestMessage("".getBytes(), keyId, null, null, null, null);
        
        EndEntityInformation userData = new EndEntityInformation();
        req.populateEndEntityData(userData, certProfile);
        
        assertEquals("SubjectDn mismatch", "", userData.getDN());
        
        userData.setDN(null);
        req = new SshRequestMessage("", "", new ExtendedInformation());
        assertEquals("keyId mismatch", keyId, req.getKeyId());
    }
    
    @Test
    public void testNullKeyId() {
        String keyId = null;
        SshRequestMessage req = new SshRequestMessage("".getBytes(), keyId, null, null, null, null);
        
        EndEntityInformation userData = new EndEntityInformation();
        req.populateEndEntityData(userData, certProfile);
        
        assertEquals("SubjectDn mismatch", "", userData.getDN());
        
        userData.setDN(null);
        req = new SshRequestMessage("", "", new ExtendedInformation());
        assertEquals("keyId mismatch", "", req.getKeyId());
    }
    
    // SAN
    // principal
    @Test
    public void testSinglePrincipal() {
        List<String> principals = new ArrayList<>();
        principals.add("onePrincipal");
        SshRequestMessage req = new SshRequestMessage("".getBytes(), "", principals, null, null, null);
        
        EndEntityInformation userData = new EndEntityInformation();
        req.populateEndEntityData(userData, certProfile);
        
        assertEquals("SAN mismatch", "dnsName=PRINCIPAL:onePrincipal:", userData.getSubjectAltName());
        
        userData.setSubjectAltName(null);
        req = new SshRequestMessage("", "dnsName=PRINCIPAL:onePrincipal:", new ExtendedInformation());
        assertEquals("principal mismatch", principals, req.getPrincipals());
    }
    
    // principal x2
    @Test
    public void testMultilePrincipal() {
        List<String> principals = new ArrayList<>();
        principals.add("onePrincipal");
        principals.add("twoPrincipal");
        SshRequestMessage req = new SshRequestMessage("".getBytes(), "", principals, null, null, null);
        
        EndEntityInformation userData = new EndEntityInformation();
        req.populateEndEntityData(userData, certProfile);
        
        assertEquals("SAN mismatch", "dnsName=PRINCIPAL:onePrincipal:twoPrincipal:", userData.getSubjectAltName());
        
        userData.setSubjectAltName(null);
        req = new SshRequestMessage("", "dnsName=PRINCIPAL:onePrincipal:twoPrincipal:", new ExtendedInformation());
        assertEquals("principal mismatch", principals, req.getPrincipals());
    }
    
    // principal x2, comment
    @Test
    public void testMultilePrincipalAndComment() {
        List<String> principals = new ArrayList<>();
        principals.add("onePrincipal");
        principals.add("twoPrincipal");
        SshRequestMessage req = new SshRequestMessage("".getBytes(), "", principals, null, null, "CommentedToo");
        
        EndEntityInformation userData = new EndEntityInformation();
        req.populateEndEntityData(userData, certProfile);
        
        assertEquals("SAN mismatch", "dnsName=PRINCIPAL:onePrincipal:twoPrincipal:COMMENT:CommentedToo", userData.getSubjectAltName());
        
        userData.setSubjectAltName(null);
        req = new SshRequestMessage("", "dnsName=PRINCIPAL:onePrincipal:twoPrincipal:COMMENT:CommentedToo", new ExtendedInformation());
        assertEquals("principal mismatch", principals, req.getPrincipals());
        assertEquals("Comment mismatch", "CommentedToo", req.getComment());
    }
    
    // comment
    @Test
    public void testOnlyComment() {
        List<String> principals = new ArrayList<>();
        SshRequestMessage req = new SshRequestMessage("".getBytes(), "", principals, null, null, "CommentedToo");
        
        EndEntityInformation userData = new EndEntityInformation();
        req.populateEndEntityData(userData, certProfile);
        
        assertEquals("SAN mismatch", "dnsName=COMMENT:CommentedToo", userData.getSubjectAltName());
        
        userData.setSubjectAltName(null);
        req = new SshRequestMessage("", "dnsName=COMMENT:CommentedToo", new ExtendedInformation());
        assertTrue("principal mismatch", req.getPrincipals().isEmpty());
        assertEquals("Comment mismatch", "CommentedToo", req.getComment());
    }
    
    // EI
    // critical: (none, each, both)
    @Test
    public void testCriticals() {
        Map<String, String> criticals = new HashMap<>();
        criticals.put("source-address", "abcd");
        criticals.put("force-action", "xyzz");
        SshRequestMessage req = new SshRequestMessage("".getBytes(), "", null, null, criticals, "CommentedToo");
        
        EndEntityInformation userData = new EndEntityInformation();
        req.populateEndEntityData(userData, certProfile);
        
        assertEquals("critical options mismatch at userdata", criticals, userData.getExtendedInformation().getSshCriticalOptions());
        
        ExtendedInformation ei = userData.getExtendedInformation();
        userData.setExtendedInformation(new ExtendedInformation());
        req = new SshRequestMessage("", "", ei);
        assertEquals("critical options mismatch at request message", criticals, req.getCriticalOptions());
    }
    
    @Test
    public void testIPv6() {
        List<String> principals = new ArrayList<>();
        principals.add("onePrincipal");
        principals.add("twoPrincipal");
        principals.add("198.172.9.18");
        principals.add("ab:cd:ef::gh");
        principals.add("ab:cd:ef:ee:gh");
        principals.add("::1");
        SshRequestMessage req = new SshRequestMessage("".getBytes(), "", principals, null, null, "CommentedToo");
        
        EndEntityInformation userData = new EndEntityInformation();
        req.populateEndEntityData(userData, certProfile);
        
        assertEquals("SAN mismatch", "dnsName=PRINCIPAL:onePrincipal:twoPrincipal:198.172.9.18:ab:cd:ef::gh:ab:cd:ef:ee:gh:::1:COMMENT:CommentedToo", userData.getSubjectAltName());
        
        userData.setSubjectAltName(null);
        ExtendedInformation ei = new ExtendedInformation();
        List<String> ipV6s = new ArrayList<>();
        ipV6s.add("ab:cd:ef::gh");
        ipV6s.add("ab:cd:ef:ee:gh");
        ipV6s.add("::1");
        ei.setSshPrincipalsIpv6(ipV6s);
        req = new SshRequestMessage("", "dnsName=PRINCIPAL:onePrincipal:twoPrincipal:198.172.9.18:ab:cd:ef::gh:ab:cd:ef:ee:gh:::1:COMMENT:CommentedToo", ei);
        assertEquals("principal mismatch", principals, req.getPrincipals());
        assertEquals("Comment mismatch", "CommentedToo", req.getComment());
    }
    
}
