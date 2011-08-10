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

package org.ejbca.core.protocol.ocsp.standalonesession;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.util.query.BasicMatch;

/**
 * An object of this class is constructed when the key should be updated.
 * 
 * @author primelars
 * @version  $Id$
 */
class KeyRenewer {
    /**
     * Log object.
     */
    static final private Logger m_log = Logger.getLogger(KeyRenewer.class);
    /**
     * The keystore containing the key to authenticate with.
     * The {@link PrivateKeyContainerKeyStore} object must delete the reference to the {@link KeyRenewer}
     * object when {@link PrivateKeyContainerKeyStore} is not used any more.
     */
    private final PrivateKeyContainerKeyStore privateKeyContainerKeyStore;
    /**
     * Defines the thread that is doing the update.
     */
    final private Runner runner;
    /**
     * True as long as the object should renew the key when needed. Set to false when all signing entitys are reloaded.
     */
    private boolean doUpdateKey;
    /**
     * The CA chain. The CA signing the certificate for the new key is on top
     */
    final private List<X509Certificate> caChain;
    /**
     * EJBCA id for the CA that will sign the new key.
     */
    final private int caid;            
    /**
     * Class used for the thread doing the renewing.
     */
    private class Runner implements Runnable {
        /* (non-Javadoc)
         * @see java.lang.Runnable#run()
         */
        public synchronized void run() {
            while( KeyRenewer.this.doUpdateKey ) {
                if ( KeyRenewer.this.privateKeyContainerKeyStore.certificate==null ) {
                    return;
                }
                final long timeToRenew = KeyRenewer.this.privateKeyContainerKeyStore.certificate.getNotAfter().getTime()-new Date().getTime()-1000*(long)KeyRenewer.this.privateKeyContainerKeyStore.sessionData.mRenewTimeBeforeCertExpiresInSeconds;
                if (m_log.isDebugEnabled()) {
                    m_log.debug("time to renew signing key for CA \'"+KeyRenewer.this.privateKeyContainerKeyStore.certificate.getIssuerDN()+"\' : "+timeToRenew );
                }
                try {
                    wait(Math.max(timeToRenew, 15000)); // set to 15 seconds if long time to renew before expire 
                } catch (InterruptedException e) {
                    throw new Error(e);
                }
                try {
                    updateKey();
                } catch( Throwable t ) {
                    m_log.error("Unknown problem when rekeying. Trying again.", t);
                }
            }
        }
    }
    /**
     * Updating of the key.
     */
    private void updateKey() {
        if ( !this.doUpdateKey ) {
            return;
        }
        this.privateKeyContainerKeyStore.sessionData.setNextKeyUpdate(new Date().getTime()); //  since a key is now reloaded we should wait an whole interval for next key update
        m_log.debug("rekeying started for CA \'"+this.privateKeyContainerKeyStore.certificate.getIssuerDN()+"\'");
        // Check that we at least potentially have a RA key available for P11 sessions
        if ("pkcs11".equalsIgnoreCase(System.getProperty("javax.net.ssl.keyStoreType")) && this.privateKeyContainerKeyStore.sessionData.mP11Password == null &&
                !this.privateKeyContainerKeyStore.sessionData.doNotStorePasswordsInMemory) {
            m_log.info("PKCS#11 slot password is not yet available. Cannot access RA admin key until token is activated.");
            return;
        }
        // TODO: If the password for the RA token was wrong, the SSL provider will crash and burn.. solve this.
        final EjbcaWS ejbcaWS = getEjbcaWS();
        if ( ejbcaWS==null ) {
            return;
        }
        final String caName = getCAName(ejbcaWS);
        if ( caName==null ) {
            m_log.debug("No CA for caid "+this.caid+" found.");
            return;
        }
        final UserDataVOWS userData=getUserDataVOWS(ejbcaWS, caName);
        if ( userData==null ) {
            return;
        }
        m_log.debug("user name found: "+ userData.getUsername());
        try {
            this.privateKeyContainerKeyStore.waitUntilKeyIsNotUsed();
            final KeyPair keyPair = generateKeyPair();
            if ( keyPair==null ) {
                return;
            }
            m_log.debug("public key: "+keyPair.getPublic() );
            if ( !editUser(ejbcaWS, userData) ) {
                return;
            }
            final X509Certificate certChain[] = storeKey(ejbcaWS, userData, keyPair);
            if ( certChain==null ) {
                return;
            }
            this.privateKeyContainerKeyStore.privateKey = keyPair.getPrivate();
            this.privateKeyContainerKeyStore.certificate = certChain[0];
        } finally {
            this.privateKeyContainerKeyStore.keyGenerationFinished();
        }
        m_log.info("New OCSP signing key generated for CA '"+ userData.getCaName()+"'. Username: '"+userData.getUsername()+"'. Subject DN: '"+userData.getSubjectDN()+"'.");
    }
    /**
     * Get WS object.
     * @return the EJBCA WS object.
     */
    private EjbcaWS getEjbcaWS() {
        final URL ws_url;
        try {
            ws_url = new URL(this.privateKeyContainerKeyStore.sessionData.webURL + "?wsdl");
        } catch (MalformedURLException e) {
            m_log.error("Problem with URL: '"+this.privateKeyContainerKeyStore.sessionData.webURL+"'", e);
            return null;
        }
        final QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        m_log.debug("web service. URL: "+ws_url+" QName: "+qname);
        return new EjbcaWSService(ws_url, qname).getEjbcaWSPort();
    }
    /**
     * Get the CA name
     * @param ejbcaWS from {@link #getEjbcaWS()}
     * @return the name
     */
    private String getCAName(EjbcaWS ejbcaWS) {
            final Map<Integer, String> mCA = new HashMap<Integer, String>();
            final Iterator<NameAndId> i;
            try {
                i = ejbcaWS.getAvailableCAs().iterator();
            } catch (Exception e) {
                m_log.error("WS not working", e);
                return null;
            }
            while( i.hasNext() ) {
                final NameAndId nameAndId = i.next();
                mCA.put(new Integer(nameAndId.getId()), nameAndId.getName());
                m_log.debug("CA. id: "+nameAndId.getId()+" name: "+nameAndId.getName());
            }
            return mCA.get(new Integer(this.caid));
    }
    /**
     * Get user data for the EJBCA user that will be used when creating the cert for the new key.
     * @param ejbcaWS from {@link #getEjbcaWS()}
     * @param caName from {@link #getCAName(EjbcaWS)}
     * @return the data
     */
    private UserDataVOWS getUserDataVOWS(EjbcaWS ejbcaWS, String caName) {
        final UserMatch match = new org.ejbca.core.protocol.ws.client.gen.UserMatch();
        final String subjectDN = CertTools.getSubjectDN(this.privateKeyContainerKeyStore.certificate);
        match.setMatchtype(BasicMatch.MATCH_TYPE_EQUALS);
        match.setMatchvalue(subjectDN);
        match.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_DN);
        final List<UserDataVOWS> result;
        try {
            result = ejbcaWS.findUser(match);
        } catch (Exception e) {
            m_log.error("WS not working", e);
            return null;
        }
        if ( result==null || result.size()<1) {
            m_log.info("no match for subject DN:"+subjectDN);
            return null;
        }
        m_log.debug("at least one user found for cert with DN: "+subjectDN+" Trying to match it with CA name: "+caName);
        UserDataVOWS userData = null;
        final Iterator<UserDataVOWS> i = result.iterator();
        while ( i.hasNext() ) {
            final UserDataVOWS tmpUserData = i.next();
            if ( caName.equals(tmpUserData.getCaName()) ) {
                userData = tmpUserData;
                break;
            }
        }
        if ( userData==null ) {
            m_log.error("No user found for certificate '"+subjectDN+"' on CA '"+caName+"'.");
            return null;
        }
        return userData;
    }
    /**
     * Generate the key.
     * @return the key
     */
    private KeyPair generateKeyPair() {

        final RSAPublicKey oldPublicKey; {
            final PublicKey tmpPublicKey = this.privateKeyContainerKeyStore.certificate.getPublicKey();
            if ( !(tmpPublicKey instanceof RSAPublicKey) ) {
                m_log.error("Only RSA keys could be renewed.");
                return null;
            }
            oldPublicKey = (RSAPublicKey)tmpPublicKey;
        }
        final KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", this.privateKeyContainerKeyStore.providerName);
            kpg.initialize(oldPublicKey.getModulus().bitLength());
            return kpg.generateKeyPair();
        } catch (Throwable e) {
            m_log.error("Key generation problem.", e);
            return null;
        }
    }
    /**
     * setting status of EJBCA user to new and setting password of user.
     * @param ejbcaWS from {@link #getEjbcaWS()}
     * @param userData from {@link #getUserDataVOWS(EjbcaWS, String)}
     * @return true if success
     */
    private boolean editUser(EjbcaWS ejbcaWS, UserDataVOWS userData) {
        userData.setStatus(UserDataConstants.STATUS_NEW);
        userData.setPassword("foo123");
        userData.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        try {
            ejbcaWS.editUser(userData);
        } catch (Exception e) {
            m_log.error("Problem to edit user.", e);
            return false;
        }
        return true;
    }
    /**
     * Fetch a new certificate from EJBCA and stores the key with the certificate chain.
     * @param ejbcaWS from {@link #getEjbcaWS()}
     * @param userData from {@link #getUserDataVOWS(EjbcaWS, String)}
     * @param keyPair from {@link #generateKeyPair()}
     * @return the certificate chain of the stored key
     */
    private X509Certificate[] storeKey(EjbcaWS ejbcaWS, UserDataVOWS userData, KeyPair keyPair) {
        X509Certificate tmpCert = null;
        final Iterator<X509Certificate> i;
        try {
            final PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOUSED"), keyPair.getPublic(), new DERSet(),
                                                                                     keyPair.getPrivate(), this.privateKeyContainerKeyStore.providerName );
            final CertificateResponse certificateResponse = ejbcaWS.pkcs10Request(userData.getUsername(), userData.getPassword(),
                                                                                  new String(Base64.encode(pkcs10.getEncoded())),null,CertificateHelper.RESPONSETYPE_CERTIFICATE);
            i = (Iterator<X509Certificate>)CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(Base64.decode(certificateResponse.getData()))).iterator();
        } catch (Exception e) {
            m_log.error("Certificate generation problem.", e);
            return null;
        }
        while ( i.hasNext() ) {
            tmpCert = i.next();
            try {
                tmpCert.verify(this.caChain.get(0).getPublicKey());
            } catch (Exception e) {
                tmpCert = null;
                continue;
            }
            if ( keyPair.getPublic().equals(tmpCert.getPublicKey()) )
                break;
            tmpCert = null;
        }
        if ( tmpCert==null ) {
            m_log.error("No certificate signed by correct CA generated.");
            return null;
        }
        final List<X509Certificate> lCertChain = new ArrayList<X509Certificate>(this.caChain);
        lCertChain.add(0, tmpCert);
        final X509Certificate certChain[] = lCertChain.toArray(new X509Certificate[0]);
        if ( this.privateKeyContainerKeyStore.fileName!=null && this.privateKeyContainerKeyStore.sessionData.mKeyPassword==null ) {
            m_log.error("Key password must be configured when updating SW keystore.");
            return null;
        }
        try {
            this.privateKeyContainerKeyStore.keyStore.setKeyEntry(this.privateKeyContainerKeyStore.alias, keyPair.getPrivate(),
                                                                  this.privateKeyContainerKeyStore.sessionData.mKeyPassword!=null ? this.privateKeyContainerKeyStore.sessionData.mKeyPassword.toCharArray() : null,
                                                                  certChain);
        } catch (Throwable e) {
            m_log.error("Problem to store new key in HSM.", e);
            return null;
        }
        if ( this.privateKeyContainerKeyStore.fileName!=null ) {
            try {
                this.privateKeyContainerKeyStore.keyStore.store(new FileOutputStream(this.privateKeyContainerKeyStore.fileName),
                                                                this.privateKeyContainerKeyStore.sessionData.mStorePassword.toCharArray());
            } catch (Throwable e) {
                m_log.error("Not possible to store keystore on file.",e);
            }
        }
        return certChain;
    }
    /**
     * Initialize renewing of keys.
     * @param privateKeyContainerKeyStore keystore to use
     * @param _caChain sets {@link #caChain}
     * @param _caid sets {@link #caid}
     */
    KeyRenewer(PrivateKeyContainerKeyStore privateKeyContainerKeyStore, List<X509Certificate> _caChain, int _caid) {
        this.privateKeyContainerKeyStore = privateKeyContainerKeyStore;
        this.caid = _caid;
        this.caChain = _caChain;
        this.doUpdateKey = false;
        if ( this.privateKeyContainerKeyStore.sessionData.doKeyRenewal() ) {
            this.runner = new Runner();
            this.doUpdateKey = true;
            new Thread(this.runner).start();
        } else {
            this.runner = null;
        }
    }
    /**
     * Shuts down the rekeying thread. Done when reloading OCSP signing keys.
     */
    void shutdown() {
        this.doUpdateKey = false;
        if ( this.runner!=null ) {
            synchronized( this.runner ) {
                this.runner.notifyAll();
            }
        }
    }
}