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

package org.ejbca.core.protocol.cmp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;

/**
 * Nested Message Content according to RFC4210. The PKI message is signed by an RA authority.
 * The PKIMessage body is another PKIMessage containing the request to be processed. 
 * 
 * @version $Id$
 *
 */
public class NestedMessageContent extends BaseCmpMessage implements RequestMessage {

    private static final long serialVersionUID = 1L;
    
    private static final Logger log = Logger.getLogger(NestedMessageContent.class);
    
    private PKIMessage raSignedMessage;
    private String confAlias;
    private CmpConfiguration cmpConfiguration;
    
    /** Because PKIMessage is not serializable we need to have the serializable bytes save as well, so 
     * we can restore the PKIMessage after serialization/deserialization. */ 
    private byte[] pkimsgbytes = null;

    public NestedMessageContent() {
        this.confAlias = null;
    }
    
    public NestedMessageContent(final PKIMessage pkiMessage, final CmpConfiguration cmpConfiguration, String configAlias) {
        this.raSignedMessage = pkiMessage;
        this.confAlias = configAlias;
        this.cmpConfiguration = cmpConfiguration;
        setPKIMessageBytes(pkiMessage);
        final PKIHeader pkiHeader = pkiMessage.getHeader();
        setTransactionId(getBase64FromAsn1OctetString(pkiHeader.getTransactionID()));
        setSenderNonce(getBase64FromAsn1OctetString(pkiHeader.getSenderNonce()));
        setRecipient(pkiHeader.getRecipient());
        setSender(pkiHeader.getSender());
    }

    public PKIMessage getPKIMessage() {
        if (getMessage() == null) {
            setMessage(PKIMessage.getInstance(pkimsgbytes));
        }
        return getMessage();
    }
    public void setPKIMessageBytes(final PKIMessage msg) {
        try {
            this.pkimsgbytes = msg.toASN1Primitive().getEncoded();
        } catch (IOException e) {
            log.error("Error getting encoded bytes from PKIMessage: ", e);
        }
        setMessage(msg);
    }

    
    @Override
    public boolean verify() {
        /*
         * Verifies the signature of the pkimessage using the trusted RA certificate stored in cmpConfiguration.getRaCertificatePath()
         */
        boolean ret = false;
        try {
            final String raCertsPath = this.cmpConfiguration.getRACertPath(this.confAlias);
            final List<X509Certificate> racerts = getRaCerts(raCertsPath);
            if (racerts.isEmpty()) {
                log.info("No certificate files were found in " + raCertsPath);
            }
            for (final X509Certificate cert : racerts) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to verifying the NestedMessageContent using the RA certificate with subjectDN '" + cert.getSubjectDN() + "'");
                }
                try {
                    cert.checkValidity();
                } catch (CertificateExpiredException | CertificateNotYetValidException e) {                  
                    if (log.isDebugEnabled()) {
                        log.debug("Certificate with subjectDN '" + CertTools.getSubjectDN(cert) + "' is not valid: " + e.getMessage());
                    }
                    continue;
                }
                if (raSignedMessage.getProtection() != null) {
                    final String algId; 
                    if (raSignedMessage.getHeader().getProtectionAlg() != null) {
                        algId = raSignedMessage.getHeader().getProtectionAlg().getAlgorithm().getId();    
                    } else {
                        algId = cert.getSigAlgName();
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Verifying message signature using algorithm id: "+algId);
                    }
                    Signature sig = Signature.getInstance(algId, BouncyCastleProvider.PROVIDER_NAME);
                    sig.initVerify(cert.getPublicKey());
                    sig.update(CmpMessageHelper.getProtectedBytes(raSignedMessage));
                    ret = sig.verify(raSignedMessage.getProtection().getBytes());
                    if (log.isDebugEnabled()) {
                        log.debug("Verifying the NestedMessageContent using the RA certificate with subjectDN '" + cert.getSubjectDN() + "' returned " + ret);
                    }
                } else {
                    log.info("No signature was found in NestedMessageContent");
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Verifying the NestedMessageContent returned " + ret);
        }
        return ret;
    }

    /**
     * Reads the files in cmpConfiguration.getRaCertificatePath() and returns them as a list of certificates.
     *  
     * The certificate files should be PEM encoded.
     * 
     * @return A list of the valid certificates in cmpConfiguration.getRaCertificatePath(). 
     */
    private List<X509Certificate> getRaCerts(final String raCertsPath) {
        final List<X509Certificate> racerts = new ArrayList<>();
        if (log.isDebugEnabled()) {
            log.debug("Looking for trusted RA certificate in " + raCertsPath);
        }
        final File raCertDirectory = new File(raCertsPath);
        final String[] files = raCertDirectory.list();
        if (files != null) {
            if (log.isDebugEnabled()) {
                log.debug("Found " + files.length + " trusted RA certificate in " + raCertsPath);
            }
            for (final String certFile : files) {
                final String filepath = raCertsPath + "/" + certFile;
                try {
                    racerts.add(CertTools.getCertsFromPEM(filepath, X509Certificate.class).iterator().next());
                    if (log.isDebugEnabled()) {
                        log.debug("Added " + certFile + " to the list of trusted RA certificates");
                    }
                } catch (CertificateParsingException | FileNotFoundException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to add " + certFile + " to the list of trusted RA certificates: " + e.getMessage());
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Found " + racerts.size() + " certificates in " + raCertsPath);
        }
        return racerts;
    }

    @Override
    public String getCRLIssuerDN() {
        return null;
    }

    @Override
    public BigInteger getCRLSerialNo() {
        return null;
    }

    @Override
    public int getErrorNo() {
        return 0;
    }

    @Override
    public String getErrorText() {
        return null;
    }

    @Override
    public String getIssuerDN() {
        return null;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getPreferredDigestAlg() {
        return null;
    }

    @Override
    public String getRequestAltNames() {
        return null;
    }

    @Override
    public String getRequestDN() {
        return null;
    }

    @Override
    public Extensions getRequestExtensions() {
        return null;
    }

    @Override
    public int getRequestId() {
        return 0;
    }

    @Override
    public byte[] getRequestKeyInfo() {
        return null;
    }

    @Override
    public PublicKey getRequestPublicKey() throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException {
        return null;
    }

    @Override
    public int getRequestType() {
        return 0;
    }

    @Override
    public Date getRequestValidityNotAfter() {
        return null;
    }

    @Override
    public Date getRequestValidityNotBefore() {
        return null;
    }

    @Override
    public X500Name getRequestX500Name() {
        return null;
    }

    @Override
    public BigInteger getSerialNo() {
        return null;
    }

    @Override
    public String getUsername() {
        return null;
    }

    @Override
    public boolean includeCACert() {
        return false;
    }

    @Override
    public boolean requireKeyInfo() {
        return false;
    }

    @Override
    public void setKeyInfo(final Certificate cert, final PrivateKey key, final String provider) {}

    
    @Override
    public void setResponseKeyInfo(PrivateKey key, String provider) {
    }

}
