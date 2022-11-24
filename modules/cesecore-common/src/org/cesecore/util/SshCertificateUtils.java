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
    
    /**
     * Extract SSH key ID from subject DN text field.
     * @param subjectDn
     * @return SSH key ID String
     */
    public static String getKeyId(String subjectDn) {
        if(StringUtils.isNotBlank(subjectDn)) {
            return subjectDn.replace("CN=", "");
        }
        return "";
    }
    
    /**
     * Extract SSH principals from subject AN text field.
     * @param subjectAlternateName
     * @return colon separated String of SSH principals
     */
    public static String getPrincipalsAsString(String subjectAlternateName) {
        return parsePrincipalsAndComment(subjectAlternateName)[0];
    }
    
    /**
     * Extract SSH comment from subject AN text field.
     * @param subjectAlternateName
     * @return String with SSH comment
     */
    public static String getComment(String subjectAlternateName) {
        return parsePrincipalsAndComment(subjectAlternateName)[1];
    }
    
    /**
     * Extract SSH principals and comment from subject AN text field.
     * @param subjectAlternateName
     * @return Array of Strings where the first element is SSH principals (colon separated) and second element is SSH comment
     */
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
    
    /**
     * Create subject AN text field for storage from SSH certificate.
     * @param sshCertificate SshCertificate object
     * @return SSH subject AN text field formatted for storage
     */
    public static String createSanForStorage(SshCertificate sshCertificate) {
        return createSanForStorage(sshCertificate.getPrincipals(), sshCertificate.getComment());
    }
    
    /**
     * Create subject AN text field for storage from list of principals and comment.
     * @param principals String containing colon separated SSH principals
     * @param comment
     * @return SSH subject AN text field formatted for storage
     */
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

    /**
     * Create subject AN text field for storage from colon separated String with SSH principals and comment.
     * @param principalString String with colon separated SSH principals
     * @param comment
     * @return SSH subject AN text field formatted for storage
     */
    public static String createSanForStorage(final String principalString, final String comment) {
        return createSanForStorage(Arrays.asList(principalString.split(":")), comment);
    }

}
