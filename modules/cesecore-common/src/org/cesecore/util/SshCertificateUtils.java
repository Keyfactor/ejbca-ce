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

import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.cesecore.certificates.certificate.ssh.SshCertificate;
import org.cesecore.certificates.certificate.ssh.SshEndEntityProfileFields;

public class SshCertificateUtils {
    
    public static String getKeyId(String subjectDn) {
        if(StringUtils.isNotBlank(subjectDn)) {
            return subjectDn.replace("CN=", "");
        }
        return "";
    }
    
    public static String getPrincipalsAsString(String subjectAlternateName) {
        return parsePrincipalsAndComment(subjectAlternateName)[0];
    }
    
    public static String getComment(String subjectAlternateName) {
        return parsePrincipalsAndComment(subjectAlternateName)[1];
    }
    
    public static String[] parsePrincipalsAndComment(String subjectAlternateName) {
        String comment = "";
        String principals = "";
        if(StringUtils.isNotBlank(subjectAlternateName)) {
            subjectAlternateName = subjectAlternateName.substring("dnsName=".length());
            int commentIndex = subjectAlternateName.indexOf(SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT);
            if(commentIndex!=0) { // no principal
                if(commentIndex==-1) {
                    commentIndex = subjectAlternateName.length(); // principal is whole content
                } else {
                    comment = subjectAlternateName.substring(commentIndex + 
                            SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT.length() + 1);
                    commentIndex--;
                }
                String allPrincipals = subjectAlternateName.substring(SshEndEntityProfileFields.SSH_PRINCIPAL.length()+1, commentIndex);
                principals = allPrincipals;
            } else {
                comment = subjectAlternateName.substring(SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT.length() + 1);
            }
            
        }
        
        return new String[] {principals, comment};
    }
    
    public static String createSanForStorage(SshCertificate sshCertificate) {
        return createSanForStorage(sshCertificate.getPrincipals(), sshCertificate.getComment());
    }
    
    public static String createSanForStorage(List<String> principals, String comment) {
        StringBuilder placeHolderSan = new StringBuilder();
        if(principals!=null && !principals.isEmpty()) {
            placeHolderSan.append(SshEndEntityProfileFields.SSH_PRINCIPAL + ":");
            for(String principal: principals) {
                if(StringUtils.isNotBlank(principal)) {
                    placeHolderSan.append(principal);
                    placeHolderSan.append(":");
                }
            }
        }
        
        if(StringUtils.isNotBlank(comment)) {
            placeHolderSan.append(SshEndEntityProfileFields.SSH_CERTIFICATE_COMMENT + ":");
            placeHolderSan.append(comment);
        }
        
        String placeHolderSanString = placeHolderSan.toString();
        if(StringUtils.isNotBlank(placeHolderSanString)) {
            return "dnsName=" + placeHolderSanString;
        }
        return "";
    }

    public static String createSanForStorage(final String principalString, final String comment) {
        return createSanForStorage(Arrays.asList(principalString.split(":")), comment);
    }

}
