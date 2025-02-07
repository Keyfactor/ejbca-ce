/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import org.cesecore.certificates.certificate.ssh.SshEndEntityProfileFields;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class SshCertificateUtilsUnitTest {

    @Test
    public void testGetKeyIdEmptySubjectDn() {
        String emptySubjectDn = "";
        assertEquals("", SshCertificateUtils.getKeyId(emptySubjectDn));
    }

    @Test
    public void testGetKeyIdNullSubjectDn() {
        String nullSubjectDn = null;
        assertEquals("", SshCertificateUtils.getKeyId(nullSubjectDn));
    }

    @Test
    public void testGetKeyIdValidSubjectDn() {
        String validSubjectDn = "CN=ssh-key-123456";
        assertEquals("ssh-key-123456", SshCertificateUtils.getKeyId(validSubjectDn));
    }

    @Test
    public void testGetKeyIdSubjectDnWithOtherComponents() {
        String subjectDnWithOtherComponents = "CN=ssh-key-123456,O=Organization,C=US";
        assertEquals("ssh-key-123456,O=Organization,C=US", SshCertificateUtils.getKeyId(subjectDnWithOtherComponents));
    }

    @Test
    public void testParsePrincipalsAndCommentNormalCase() {
        String principalsAndCommentInput = "dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:" +
                SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":User certificate for Alice and Bob";
        String[] result = SshCertificateUtils.parsePrincipalsAndComment(principalsAndCommentInput);
        assertEquals("alice:bob", result[0]);
        assertEquals("User certificate for Alice and Bob", result[1]);
    }

    @Test
    public void testParsePrincipalsAndCommentOnlyPrincipals() {
        String onlyPrincipalsInput = "dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:alice@example.com:*.example.com";
        String[] resultOnlyPrincipals = SshCertificateUtils.parsePrincipalsAndComment(onlyPrincipalsInput);
        assertEquals("alice:bob:alice@example.com:*.example.com", resultOnlyPrincipals[0]);
        assertEquals("", resultOnlyPrincipals[1]);
    }

    @Test
    public void testParsePrincipalsAndCommentOnlyComment() {
        String onlyCommentInput = "dnsName=" + SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + " User certificate for Alice and Bob";
        String[] resultOnlyComment = SshCertificateUtils.parsePrincipalsAndComment(onlyCommentInput);
        assertEquals("", resultOnlyComment[0]);
        assertEquals("User certificate for Alice and Bob", resultOnlyComment[1]);
    }

    @Test
    public void testParsePrincipalsAndCommentEmptyInput() {
        String emptyInput = "";
        String[] resultEmpty = SshCertificateUtils.parsePrincipalsAndComment(emptyInput);
        assertEquals("", resultEmpty[0]);
        assertEquals("", resultEmpty[1]);
    }

    @Test
    public void testParsePrincipalsAndCommentInputWithRfc822Name() {
        String inputWithRfc822Name = "dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:" +
                SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":User certificate rfc822Name=alice@example.com";
        String[] resultRfc822Name = SshCertificateUtils.parsePrincipalsAndComment(inputWithRfc822Name);
        assertEquals("alice:bob", resultRfc822Name[0]);
        assertEquals("User certificate", resultRfc822Name[1]);
    }

    @Test
    public void testParsePrincipalsAndCommentInputWithIPv6Address() {
        String inputWithIPv6Address = "dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:2001:db8::1:bob:" +
                SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":Certificate with IPv6";
        String[] resultWithIPV6 = SshCertificateUtils.parsePrincipalsAndComment(inputWithIPv6Address);
        assertEquals("alice:2001:db8::1:bob", resultWithIPV6[0]);
        assertEquals("Certificate with IPv6", resultWithIPV6[1]);
    }

    @Test
    public void testCreateSanForStorageNormalCase() {
        List<String> principals = Arrays.asList("alice", "bob");
        String comment = "Test certificate";
        String sourceAddress = "192.168.1.1,10.0.0.1";
        String sanForStorage = SshCertificateUtils.createSanForStorage(principals, comment, sourceAddress);
        assertEquals("dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:" +
                     SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":Test certificate," +
                     "rfc822Name=192.168.1.1:10.0.0.1", sanForStorage);
    }

    @Test
    public void testCreateSanForStorageOnlyPrincipals() {
        List<String> onlyPrincipals = Arrays.asList("alice", "bob", "charlie");
        String sanForStorage = SshCertificateUtils.createSanForStorage(onlyPrincipals, null, null);
        assertEquals("dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:charlie:", sanForStorage);
    }

    @Test
    public void testCreateSanForStorageOnlyComment() {
        String onlyComment = "Just a comment";
        String sanForStorage = SshCertificateUtils.createSanForStorage(new ArrayList<>(), onlyComment, null);
        assertEquals("dnsName=" + SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":Just a comment", sanForStorage);
    }

    @Test
    public void testCreateSanForStorageOnlySourceAddress() {
        String onlySourceAddress = "192.168.1.1";
        String sanForStorage = SshCertificateUtils.createSanForStorage(new ArrayList<>(), null, onlySourceAddress);
        assertEquals("rfc822Name=192.168.1.1", sanForStorage);
    }

    @Test
    public void testCreateSanForStorageEmptyInput() {
        String sanForStorage = SshCertificateUtils.createSanForStorage(new ArrayList<>(), "", "");
        assertEquals("", sanForStorage);
    }
}