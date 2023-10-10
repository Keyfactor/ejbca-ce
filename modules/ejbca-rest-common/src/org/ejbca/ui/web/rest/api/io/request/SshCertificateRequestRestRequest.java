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
package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.annotations.ApiModelProperty;
import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificate.ssh.SshKeyFactory;
import org.cesecore.certificates.certificate.ssh.SshPublicKey;
import org.ejbca.core.protocol.ssh.SshRequestMessage;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.validator.ValidSshCertificateRestRequest;

import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;
import javax.xml.bind.DatatypeConverter;

/**
 * A class representing the input for SSH certificate request REST method.
 */
@ValidSshCertificateRestRequest
public class SshCertificateRequestRestRequest {

    @ApiModelProperty(value = "End Entity profile name", example = "ExampleEEP")
    private String endEntityProfile;
    @ApiModelProperty(value = "Certificate profile name", example = "ENDUSER")
    private String certificateProfile;
    @ApiModelProperty(value = "Certificate Authority (CA) name", example = "ExampleCA")
    private String certificateAuthority;
    @ApiModelProperty(value = "SSH Key Identifier", example = "ski-02")
    private String keyId;
    @ApiModelProperty(value = "Comment", example = "Yellow fish under blue water")
    private String comment;
    @ApiModelProperty(value = "Public Key", example = "ssh-rsa AAA...EWj")
    private String publicKey;
    @ApiModelProperty(value = "Valid principals", example = "[\"Wishman\", \"Bradman\"]")
    private List<String> principals;
    @ApiModelProperty(value = "Critical options")
    private SshCriticalOptions criticalOptions;
    @ApiModelProperty(hidden = true) // Support in future
    private Map<String, byte[]> additionalExtensions;
    @ApiModelProperty(value = "Username", example = "JohnDoe")
    private String username;
    @ApiModelProperty(value = "Password", example = "foo123")
    private String password;
    @ApiModelProperty(value = "Valid notBefore date", example = "ISO 8601 Date string, eg. '2023-06-15T14:07:09Z'")
    private String notBefore;
    @ApiModelProperty(value = "Valid notAfter date", example = "ISO 8601 Date string, eg. '2024-06-15T14:07:09Z'")
    private String notAfter;

    public SshCertificateRequestRestRequest() {
    }

    public SshCertificateRequestRestRequest(String endEntityProfile, String certificateProfile, 
            String certificateAuthority, String keyId, String comment, String publicKey, 
            List<String> principals, SshCriticalOptions criticalOptions, Map<String, byte[]> additionalExtensions, 
            String username, String serialNumber, String password, String notBefore, String notAfter) {
        this.endEntityProfile = endEntityProfile;
        this.certificateProfile = certificateProfile;
        this.certificateAuthority = certificateAuthority;
        this.keyId = keyId;
        this.comment = comment;
        this.publicKey = publicKey;
        this.principals = principals;
        this.criticalOptions = criticalOptions;
        this.additionalExtensions = additionalExtensions;
        this.username = username;
        this.password = password;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public String getEndEntityProfile() {
        return endEntityProfile;
    }

    public void setEndEntityProfile(String endEntityProfile) {
        this.endEntityProfile = endEntityProfile;
    }

    public String getCertificateProfile() {
        return certificateProfile;
    }

    public void setCertificateProfile(String certificateProfile) {
        this.certificateProfile = certificateProfile;
    }

    public String getCertificateAuthority() {
        return certificateAuthority;
    }

    public void setCertificateAuthority(String certificateAuthority) {
        this.certificateAuthority = certificateAuthority;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public List<String> getPrincipals() {
        return principals;
    }

    public void setPrincipals(List<String> principals) {
        this.principals = principals;
    }

    public SshCriticalOptions getCriticalOptions() {
        return criticalOptions;
    }

    public void setCriticalOptions(SshCriticalOptions criticalOptions) {
        this.criticalOptions = criticalOptions;
    }

    public Map<String, byte[]> getAdditionalExtensions() {
        return additionalExtensions;
    }

    public void setAdditionalExtensions(Map<String, byte[]> additionalExtensions) {
        this.additionalExtensions = additionalExtensions;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    
    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static SshCertificateRequestRestRequestConverter converter() {
        return new SshCertificateRequestRestRequestConverter();
    }

    /**
     * Converter instance for this class.
     */
    public static class SshCertificateRequestRestRequestConverter {

        /**
         * Converts a sshCertificateRequestRestRequest into SshRequestMessage.
         *
         * @param sshCertificateRequestRestRequest input.
         *
         * @return SshRequestMessage instance.
         * @throws RestException 
         */
        public SshRequestMessage toSshRequestMessage(final SshCertificateRequestRestRequest sshCertificateRequestRestRequest) 
                throws IOException, SshKeyException, InvalidKeySpecException, RestException {
            SshPublicKey pubKey = SshKeyFactory.INSTANCE.extractSshPublicKeyFromFile(sshCertificateRequestRestRequest.getPublicKey().getBytes());
            final byte[] sshPublicKey = pubKey.encode();

            Map<String, String> criticalOptionsMsg = new HashMap<>();
            SshCriticalOptions criticalOptionsRequest = sshCertificateRequestRestRequest.getCriticalOptions();
            if (criticalOptionsRequest!=null) {
                String forceCommand = criticalOptionsRequest.getForceCommand();
                if (StringUtils.isNotBlank(forceCommand)) {
                    criticalOptionsMsg.put("force-command", forceCommand);
                }
                String sourceAddress = criticalOptionsRequest.getSourceAddress();
                if (StringUtils.isNotBlank(forceCommand)) {
                    criticalOptionsMsg.put("source-address", sourceAddress);
                }
            }
            return new SshRequestMessage.Builder()
                .keyId(sshCertificateRequestRestRequest.getKeyId())
                .comment(sshCertificateRequestRestRequest.getComment())
                .publicKey(sshPublicKey)
                .principals(sshCertificateRequestRestRequest.getPrincipals())
                .criticalOptions(criticalOptionsMsg)
                .additionalExtensions(sshCertificateRequestRestRequest.getAdditionalExtensions())
                .username(sshCertificateRequestRestRequest.getUsername())
                .password(sshCertificateRequestRestRequest.getPassword())
                .notBefore(getValidatedDate(sshCertificateRequestRestRequest.getNotBefore()))
                .notAfter(getValidatedDate(sshCertificateRequestRestRequest.getNotAfter()))
                .build();
        }
    }
    
    private static Date getValidatedDate(String sDate) throws RestException {
        Date date = null;
        if (sDate != null) {
            try {
                date = DatatypeConverter.parseDateTime(sDate).getTime();
            } catch (IllegalArgumentException e) {
                throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), sDate + " is not a valid ISO8601 date. Example of a valid date: 2022-06-07T23:55:59+02:00");
            }
        }
        return date;
    }
}
