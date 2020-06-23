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
package org.ejbca.core.protocol.ws.objects;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

/**
 * @version $Id$
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "sshRequestMessageWs", propOrder = {
    "publicKey",
    "keyId",
    "principals",
    "additionalExtensions",
    "criticalOptions",
    "comment"
})
public class SshRequestMessageWs implements Serializable {

    private static final long serialVersionUID = 1L;
    private String keyId;
    private String comment;
    private byte[] publicKey;
    private List<String> principals;
    private Map<String, String> criticalOptions;
    private Map<String, byte[]> additionalExtensions;
    
    public SshRequestMessageWs() {
        
    }

    /**
     * Constructs a request message for an SSH certificate
     * 
     * @param keyId the requested key ID
     * @param comment a comment to append to the end of the certificate, can be left bland
     * @param publicKey the public key to be signed, either an encoded Java {@link PublicKey} or a public key in SSH format as a byte array
     * @param principals a list of principals for the certificate. Leaving blank will create a wildcard certificate
     * @param criticalOptions the critical options to use
     * @param additionalExtensions any additional extensions besides those defined in the certificate profile, if allowed
     */
    public SshRequestMessageWs(String keyId, String comment, byte[] publicKey, List<String> principals, Map<String, String> criticalOptions,
            Map<String, byte[]> additionalExtensions) {
        super();
        this.keyId = keyId;
        this.comment = comment;
        this.publicKey = publicKey;
        this.principals = principals;
        this.criticalOptions = criticalOptions;
        this.additionalExtensions = additionalExtensions;
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

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public List<String> getPrincipals() {
        return principals;
    }

    public void setPrincipals(List<String> principals) {
        this.principals = principals;
    }

    public Map<String, String> getCriticalOptions() {
        return criticalOptions;
    }

    public void setCriticalOptions(Map<String, String> criticalOptions) {
        this.criticalOptions = criticalOptions;
    }

    public Map<String, byte[]> getAdditionalExtensions() {
        return additionalExtensions;
    }

    public void setAdditionalExtensions(Map<String, byte[]> additionalExtensions) {
        this.additionalExtensions = additionalExtensions;
    }

}
