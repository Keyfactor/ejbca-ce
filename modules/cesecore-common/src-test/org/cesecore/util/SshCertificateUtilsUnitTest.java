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
    public void testGetKeyId() {
        String emptySubjectDn = "";
        String nullSubjectDn = null;
        String validSubjectDn = "CN=ssh-key-123456";
        String subjectDnWithOtherComponents = "CN=ssh-key-123456,O=Organization,C=US";

        assertEquals("", SshCertificateUtils.getKeyId(emptySubjectDn));
        assertEquals("", SshCertificateUtils.getKeyId(nullSubjectDn));
        assertEquals("ssh-key-123456", SshCertificateUtils.getKeyId(validSubjectDn));
        assertEquals("ssh-key-123456,O=Organization,C=US", SshCertificateUtils.getKeyId(subjectDnWithOtherComponents));
    }

    @Test
    public void testParsePrincipalsAndComment() {
        // Test case 1: Normal case with principals and comment
        String principalsAndCommentInput = "dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:" +
                SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":User certificate for Alice and Bob";
        String[] result1 = SshCertificateUtils.parsePrincipalsAndComment(principalsAndCommentInput);
        assertEquals("alice:bob", result1[0]);
        assertEquals("User certificate for Alice and Bob", result1[1]);

        // Test case 2: Only principals, no comment
        String onlyPrincipalsInput = "dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:alice@example.com:*.example.com";
        String[] result2 = SshCertificateUtils.parsePrincipalsAndComment(onlyPrincipalsInput);
        assertEquals("alice:bob:alice@example.com:*.example.com", result2[0]);
        assertEquals("", result2[1]);

        // Test case 3: Only comment, no principals
        String onlyCommentInput = "dnsName=" + SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + " User certificate for Alice and Bob";
        String[] result3 = SshCertificateUtils.parsePrincipalsAndComment(onlyCommentInput);
        assertEquals("", result3[0]);
        assertEquals("User certificate for Alice and Bob", result3[1]);

        // Test case 4: Empty input
        String emptyInput = "";
        String[] result4 = SshCertificateUtils.parsePrincipalsAndComment(emptyInput);
        assertEquals("", result4[0]);
        assertEquals("", result4[1]);

        // Test case 5: Input with rfc822Name
        String inputWithRfc822Name = "dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:" +
                SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":User certificate rfc822Name=alice@example.com";
        String[] result5 = SshCertificateUtils.parsePrincipalsAndComment(inputWithRfc822Name);
        assertEquals("alice:bob", result5[0]);
        assertEquals("User certificate", result5[1]);

        // Test case 6: Input with IPv6 address as principal
        String inputWithIPv6Address = "dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:2001:db8::1:bob:" +
                SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":Certificate with IPv6";
        String[] result6 = SshCertificateUtils.parsePrincipalsAndComment(inputWithIPv6Address);
        assertEquals("alice:2001:db8::1:bob", result6[0]);
        assertEquals("Certificate with IPv6", result6[1]);
    }

    @Test
    public void testCreateSanForStorage() {
        // Test case 1: Normal case with principals, comment, and source address
        List<String> principals = Arrays.asList("alice", "bob");
        String comment = "Test certificate";
        String sourceAddress = "192.168.1.1,10.0.0.1";
        String result1 = SshCertificateUtils.createSanForStorage(principals, comment, sourceAddress);
        assertEquals("dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:" +
                     SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":Test certificate," +
                     "rfc822Name=192.168.1.1:10.0.0.1", result1);

        // Test case 2: Only principals, no comment or source address
        List<String> onlyPrincipals = Arrays.asList("alice", "bob", "charlie");
        String result2 = SshCertificateUtils.createSanForStorage(onlyPrincipals, null, null);
        assertEquals("dnsName=" + SshEndEntityProfileFields.SSH_PRINCIPAL + ":alice:bob:charlie:", result2);

        // Test case 3: Only comment, no principals or source address
        String onlyComment = "Just a comment";
        String result3 = SshCertificateUtils.createSanForStorage(new ArrayList<>(), onlyComment, null);
        assertEquals("dnsName=" + SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":Just a comment", result3);

        // Test case 4: Only source address, no principals or comment
        String onlySourceAddress = "192.168.1.1";
        String result4 = SshCertificateUtils.createSanForStorage(new ArrayList<>(), null, onlySourceAddress);
        assertEquals("rfc822Name=192.168.1.1", result4);

        // Test case 5: Empty input
        String result5 = SshCertificateUtils.createSanForStorage(new ArrayList<>(), "", "");
        assertEquals("", result5);
    }
}
