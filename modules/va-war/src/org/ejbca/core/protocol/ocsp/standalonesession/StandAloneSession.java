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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;

import org.apache.log4j.Logger;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.ocsp.OCSPData;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
import org.ejbca.ui.web.protocol.OCSPServletStandAlone;
import org.ejbca.util.keystore.P11Slot;
import org.ejbca.util.keystore.P11Slot.P11SlotUser;
import org.ejbca.util.provider.TLSProvider;

/** 
 * This instance is created when the OCSP Servlet session is initiated with {@link OCSPServletStandAlone#init()}. It will be only one instance of this class.
 * 
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
class StandAloneSession implements P11SlotUser,  OCSPServletStandAlone.IStandAloneSession {

    /**
     * Log object.
     */
    static private final Logger m_log = Logger.getLogger(StandAloneSession.class);
    /**
     * Internal localization of logs and errors
     */
    static private final InternalResources intres = InternalResources.getInstance();
	/**
	 * Reference to an object that holds all entities used for the OCSP signing.
	 */
	final private SigningEntityContainer signEntitycontainer;
    /**
     * The data of the session.
     */
    final private SessionData sessionData;
    /**
     * Called when a servlet is initialized. This should only occur once.
     * 
     * @param _servlet The servlet object.
     * @throws ServletException
     */
    StandAloneSession(OCSPData tmpData) throws ServletException {
        try {
            final String storePassword = OcspConfiguration.getStorePassword();
            final String cardPassword = OcspConfiguration.getCardPassword();
            final boolean doNotStorePasswordsInMemory = OcspConfiguration.getDoNotStorePasswordsInMemory();
            final String p11Password = OcspConfiguration.getP11Password();
            if ( doNotStorePasswordsInMemory ) {
                final Set<String> sError = new HashSet<String>();
                if ( storePassword!=null ) {
                    sError.add(OcspConfiguration.STORE_PASSWORD);
                }
                if ( p11Password!=null ) {
                    sError.add(OcspConfiguration.P11_PASSWORD);
                }
                if ( cardPassword!=null ) {
                    sError.add(OcspConfiguration.CARD_PASSWORD);
                }
                final StringWriter sw = new StringWriter();
                final PrintWriter pw = new PrintWriter(sw);
                if ( sError.size()>0 ) {
                    pw.print("When "+OcspConfiguration.DO_NOT_STORE_PASSWORDS_IN_MEMORY+" is configured you must remove these configurations: \"");
                    final Iterator<String> i = sError.iterator();
                    while( i.hasNext() ) {
                        pw.print(i.next());
                        if ( i.hasNext() )
                            pw.print("\" and \"");
                    }
                    pw.println("\".");
                }
                if ( OcspConfiguration.getSigningCertsValidTime()>0 ) {
                    pw.println("You must set "+OcspConfiguration.SIGNING_CERTD_VALID_TIME+" to 0 if "+OcspConfiguration.DO_NOT_STORE_PASSWORDS_IN_MEMORY+" is configured.");
                }
                pw.flush(); pw.close();
                final String error = sw.toString();
                if ( error!=null && error.length()>0 ) {
                    throw new ServletException(error);
                }
            }
            final boolean isIndex;
            final String sharedLibrary = OcspConfiguration.getSharedLibrary();
            final String configFile = OcspConfiguration.getSunP11ConfigurationFile();
            final P11Slot slot;
            if ( sharedLibrary!=null && sharedLibrary.length()>0 ) {
                final String sSlot;
                final String sSlotRead = OcspConfiguration.getSlot();
                if ( sSlotRead==null || sSlotRead.length()<1 ) {
                    throw new ServletException("No slot number given.");
                }
                final char firstChar = sSlotRead.charAt(0);
                if ( firstChar=='i'||firstChar=='I' ) {
                    sSlot = sSlotRead.substring(1).trim();
                    isIndex = true;
                } else {
                    sSlot = sSlotRead.trim();
                    isIndex = false;
                }
                slot = P11Slot.getInstance(sSlot, sharedLibrary, isIndex, null, this, 0); // no CA, set id to 0 to indicate just one juser
    			m_log.debug("sharedLibrary is: "+sharedLibrary);
            } else if ( configFile!=null && configFile.length()>0 ) {
                slot = P11Slot.getInstance(configFile, this, 0); // no CA set caid to 0 to indicate only one user
                m_log.debug("Sun P11 configuration file is: "+configFile);
            } else {
                slot = null;
            	m_log.debug("No shared P11 library.");
            }
            final String keystoreDirectoryName = OcspConfiguration.getSoftKeyDirectoryName();
            if ( keystoreDirectoryName==null || keystoreDirectoryName.length()<1 ) {
            	throw new ServletException(intres.getLocalizedMessage("ocsp.errornovalidkeys"));
            }
            m_log.debug("softKeyDirectoryName is: "+keystoreDirectoryName);
            final String webURL = OcspConfiguration.getEjbcawsracliUrl();
            final int renewTimeBeforeCertExpiresInSeconds = OcspConfiguration.getRenewTimeBeforeCertExpiresInSeconds();
            if ( webURL!=null && webURL.length()>0 ){
                if ( renewTimeBeforeCertExpiresInSeconds<0 ) {
                    throw new ServletException(OcspConfiguration.RENEW_TIMR_BEFORE_CERT_EXPIRES_IN_SECONDS+" must be defined if "+OcspConfiguration.REKEYING_WSURL+" is defined.");
                }
                final String wsSwKeystorePath = OcspConfiguration.getWsSwKeystorePath();
                // Setting system properties to ssl resources to be used
                if ( wsSwKeystorePath!=null && wsSwKeystorePath.length()>0 ) {
                    final String password = OcspConfiguration.getWsSwKeystorePassword();
                    if ( password==null ) {
                        throw new ServletException(OcspConfiguration.WSSWKEYSTOREPASSWORD+" must be specified if "+OcspConfiguration.WSSWKEYSTOREPATH+" is specified.");
                    }
                    System.setProperty("javax.net.ssl.keyStore", wsSwKeystorePath);
                    System.setProperty("javax.net.ssl.keyStorePassword", password);
                } else if ( slot!=null ) {
                    System.setProperty("javax.net.ssl.keyStoreType", "pkcs11");
                    final String sslProviderName = slot.getProvider().getName();
                    if ( sslProviderName==null ) {
                        throw new ServletException("Problem with provider. No name.");
                    }
                    m_log.debug("P11 provider name for WS: "+sslProviderName);
                    System.setProperty("javax.net.ssl.keyStoreProvider", sslProviderName);
                    System.setProperty("javax.net.ssl.trustStore", "NONE");
                    System.setProperty("javax.net.ssl.keyStore", "NONE");
                } else {
                    throw new ServletException("If "+OcspConfiguration.REKEYING_WSURL+" is defined, either "+OcspConfiguration.WSSWKEYSTOREPATH+" or P11 must be defined.");
                }
                // setting ejbca trust provider that accept all server certs
                final Provider tlsProvider = new TLSProvider();
                Security.addProvider(tlsProvider);
                Security.setProperty("ssl.TrustManagerFactory.algorithm", "AcceptAll");
                Security.setProperty("ssl.KeyManagerFactory.algorithm", "NewSunX509");
            } else {
                if ( renewTimeBeforeCertExpiresInSeconds>=0 ) {
                    throw new ServletException(OcspConfiguration.RENEW_TIMR_BEFORE_CERT_EXPIRES_IN_SECONDS+" must not be defined if "+OcspConfiguration.REKEYING_WSURL+" is not defined.");
                }
                m_log.debug("Key renewal is not enabled.");
            }
            // Load OCSP responders private keys into cache in init to speed things up for the first request
            // signEntityMap is also set
            final Set<String> keyAlias;
            {
                final String aKeyAlias[] = OcspConfiguration.getKeyAlias();
                keyAlias = aKeyAlias!=null && aKeyAlias.length>0 ? new HashSet<String>(Arrays.asList(aKeyAlias)) : null;
            }
            this.sessionData = new SessionData(slot, tmpData, webURL, renewTimeBeforeCertExpiresInSeconds, storePassword, cardPassword, keystoreDirectoryName, keyAlias, doNotStorePasswordsInMemory, p11Password);
            this.signEntitycontainer = new SigningEntityContainer(this.sessionData);
            loadPrivateKeys(tmpData.m_adm, null);
        } catch( ServletException e ) {
            throw e;
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.IStandAloneSession#healthCheck(boolean, boolean)
     */
    public String healthCheck( boolean doSignTest, boolean doValidityTest) {
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw);
        try {
            final Collection<SigningEntity> entityColleaction = this.signEntitycontainer!=null && this.signEntitycontainer.getSigningEntityMap()!=null ? this.signEntitycontainer.getSigningEntityMap().values() : null;
            if ( entityColleaction==null || entityColleaction.size()<1 ) {
                final String errMsg = intres.getLocalizedMessage("ocsp.errornosignkeys");
                pw.println();
                pw.print(errMsg);
                m_log.error(errMsg);
            } else {
                final Iterator<SigningEntity> i = entityColleaction.iterator();
                while ( i.hasNext() ) {
                    final SigningEntity signingEntity = i.next();
                    final String errMsg = intres.getLocalizedMessage("ocsp.errorocspkeynotusable", signingEntity.getCertificateChain()[1].getSubjectDN(), signingEntity.getCertificateChain()[0].getSerialNumber().toString(16));
                    if ( !signingEntity.isOK() ) {
                        pw.println();
                        pw.print(errMsg);
                        m_log.error("No key available. "+errMsg);
                        continue;
                    }
                    final PrivateKey privKey = signingEntity.keyContainer.getKey();
                    if ( privKey==null ) {
                        pw.println();
                        pw.print(errMsg);
                        m_log.error("No key available. "+errMsg);
                        continue;
                    }
                    try {
                        final String providerName = signingEntity.providerHandler.getProviderName();
                        final X509Certificate entityCert = signingEntity.keyContainer.getCertificate(); // must be after getKey
                        if ( doValidityTest && !OCSPUtil.isCertificateValid(entityCert) ) {
                            pw.println();
                            pw.print(errMsg);
                            continue;
                        }
                        final boolean isOK = !doSignTest || SessionData.signTest(privKey, entityCert.getPublicKey(),
                                                                                 entityCert.getSubjectDN().toString(), providerName);
                        if ( !isOK ) {
                            pw.println();
                            pw.print(errMsg);
                            m_log.error("Key not working. "+errMsg);
                            continue;
                        }
                        if (m_log.isDebugEnabled()) {
                            m_log.debug("Test of \""+errMsg+"\" OK!");                        	
                        }
                    } finally {
                        signingEntity.keyContainer.releaseKey();
                    }
                }
            }
        } catch (Exception e) {
            final String errMsg = intres.getLocalizedMessage("ocsp.errorloadsigningcerts");
            m_log.error(errMsg, e);
            pw.print(errMsg + ": "+e.getMessage());
        }
        pw.flush();
        return sw.toString();
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.IStandAloneSession#loadPrivateKeys(org.ejbca.core.model.log.Admin, java.lang.String)
     */
    public void loadPrivateKeys(Admin adm, String password) throws Exception {
        if ( this.sessionData.doNotStorePasswordsInMemory ) {
            if ( password==null ) {
                return; // can not load without password.
            }
            this.signEntitycontainer.loadPrivateKeys(adm, password);
            return;
        }
        if ( password==null ) {
            this.signEntitycontainer.loadPrivateKeys(adm, null);
            return;
        }
        if ( this.sessionData.mKeyPassword==null ) {
            this.sessionData.mKeyPassword=password;
        }
        if ( this.sessionData.mStorePassword==null ) {
            this.sessionData.mStorePassword=password;
        }
        if ( this.sessionData.mP11Password==null ) {
            this.sessionData.mP11Password=password;
        }
        if ( this.sessionData.cardPassword==null ) {
            this.sessionData.cardPassword = password;
        }
        this.signEntitycontainer.loadPrivateKeys(adm, null);
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.IStandAloneSession#extendedService(int, org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest)
     */
    public OCSPCAServiceResponse extendedService(int caid, OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException {
        final Map<Integer, SigningEntity> map = this.signEntitycontainer.getSigningEntityMap();
        SigningEntity se = null;
        if ( map!=null ) {
            se = map.get(new Integer(caid));
            if ( se==null ) {
                if (m_log.isDebugEnabled()) {
                    m_log.debug("No key is available for caid=" + caid + " even though a valid certificate was present. Trying to use the default responder's key instead.");
                }
                se = map.get(new Integer(this.sessionData.data.getCaid(null)));	// Use the key issued by the default responder ID instead
            }
        }
        if ( se==null ) {
            final ExtendedCAServiceNotActiveException e = new ExtendedCAServiceNotActiveException("No ocsp signing key for caid "+caid);
            synchronized(e) {
                try {
                    e.wait(10000); // calm down the client
                } catch (InterruptedException e1) {
                    throw new Error("Should never ever happend", e);
                }
            }
            throw e;
        }
        final SignerThread runnable = new SignerThread(se,request);
        final Thread thread = new Thread(runnable);
        thread.start();
        final OCSPCAServiceResponse result = runnable.getSignResult();
        thread.interrupt();
        return result;
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.P11Slot.P11SlotUser#deactivate()
     */
    public boolean deactivate() throws Exception {
        this.sessionData.slot.logoutFromSlotIfNoTokensActive();
        // should allways be active
        return true;
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.P11Slot.P11SlotUser#isActive()
     */
    public boolean isActive() {
        return this.sessionData.doNotStorePasswordsInMemory; // if not active it is possible to logout from the slot. if logged out you need password to login again.
    }
}
