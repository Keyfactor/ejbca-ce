/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.util.CertTools;

/**
 * Represents an entry in the token with at minimum an alias and a type.
 *
 * @version $Id$
 */
public class TokenEntry implements Serializable {

    private static final long serialVersionUID = 1L;
    
    public static final String TYPE_PRIVATEKEY_ENTRY = "PRIVATEKEY_ENTRY";
    public static final String TYPE_SECRETKEY_ENTRY = "SECRETKEY_ENTRY";
    public static final String TYPE_TRUSTED_ENTRY = "TRUSTED_ENTRY";
    
    private final String alias;
    private final String type;

    private byte[][] chain;
    private transient Certificate[] parsedChain; // Certificate might not be serializable
    private byte[] trustedCertificate;
    private transient Certificate parsedTrustedCertificate; // Certificate might not be serializable
    private Date creationDate;
    
    private Map<String, String> info;
        
    public TokenEntry(String alias, String type) {
        this.alias = alias;
        this.type = type;
    }
    
    public String getType() {
        return this.type;
    }

    public void setCreationDate(Date creationDate) {
        this.creationDate = creationDate;
    }

    public void setParsedChain(Certificate[] chain) throws CertificateEncodingException {
        this.chain = new byte[chain.length][];
        for (int i = 0; i < chain.length; i++) {
            this.chain[i] = chain[i].getEncoded();
        }
        this.parsedChain = chain;
    }
    
    public Certificate[] getParsedChain() throws CertificateException {
        if (this.parsedChain == null && this.chain != null) {
            this.parsedChain = new Certificate[this.chain.length];
            int i = 0;
            for (byte[] certBytes : this.chain) {
                this.parsedChain[i] = CertTools.getCertfromByteArray(certBytes, BouncyCastleProvider.PROVIDER_NAME, Certificate.class);
                i++;
            }
        }
        return this.parsedChain;
    }
    
    public byte[][] getChain() {
        return chain;
    }
    
    public void setChain(byte[][] chain) {
        if (this.chain != chain) {
            this.parsedChain = null;
        }
        this.chain = chain;
    }

    public String getAlias() {
        return alias;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public byte[] getTrustedCertificate() {
        return trustedCertificate;
    }

    public void setTrustedCertificate(byte[] trustedCertificate) {
        this.trustedCertificate = trustedCertificate;
    }

    public Certificate getParsedTrustedCertificate() throws CertificateException {
        if (this.parsedTrustedCertificate == null && this.trustedCertificate != null) {
            this.parsedTrustedCertificate = CertTools.getCertfromByteArray(this.trustedCertificate, BouncyCastleProvider.PROVIDER_NAME, Certificate.class);
        }
        return this.parsedTrustedCertificate;
    }

    public void setParsedTrustedCertificate(Certificate parsedTrustedCertificate) throws CertificateEncodingException {
        this.trustedCertificate = parsedTrustedCertificate.getEncoded();
        this.parsedTrustedCertificate = parsedTrustedCertificate;
    }
    
    public void setInfo(Map<String, String> info) {
        this.info = info;
    }
    
    public Map<String, String> getInfo() {
        return this.info;
    }    

    @Override
    public String toString() {
        return "TokenEntry{" + "alias=" + alias + '}';
    }
    
}
