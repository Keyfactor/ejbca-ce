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

 package org.ejbca.core.model.ca.catoken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;


/** This class implements support for the nCipher nFast HSM for storing CA keys.
 * This implementation was done by PrimeKey Solutions AB (www.primekey.se) in 2005 
 * and the development was sponsored by Linagora (www.linagora.com).
 * 
 * @author Lars Silven
 * @version $Id$
 */
public class NFastCAToken extends BaseCAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(NFastCAToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    static final public String SLOT_LABEL_KEY = "keyStore";
    static final private String PROVIDER_CLASS = "com.ncipher.provider.km.nCipherKM";

    static final private String PROVIDER_CLASS_JCE = "com.ncipher.fixup.provider.nCipherRSAPrivateEncrypt";

    private KeyStore keyStore; // The used keystore has to be saved. Otherwise the used keys of the store are destroyed when the 
                               // KeyStore destructor is called after the reference is lost. This is a workaround for a nCipher bug.

    /** The constructor of HardCAToken should throw an InstantiationException if the token can not
     * be created, if for example depending jar files for the particular HSM is not available.
     * @throws InstantiationException
     * @throws IllegalAccessException if the nCipher provider is not available
     */
    public NFastCAToken() throws InstantiationException, IllegalAccessException {
        super(PROVIDER_CLASS);
        log.debug("Creating NFastCAToken");
    }

    private KeyStore getKeyStore(String authCode) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        final KeyStore ks = KeyStore.getInstance("nCipher.sworld");
        try {
            ks.load(new ByteArrayInputStream(sSlotLabel.getBytes()),
                    null);
        } catch( Exception e) {
            log.debug("Preload maybe not called. Assuming 1/N. Exception was:",e);
            ks.load(new ByteArrayInputStream(sSlotLabel.getBytes()),
            		(authCode!=null && authCode.length()>0)? authCode.toCharArray():null );
        }
        return ks;
    }
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.ICAToken#activate(java.lang.String)
     */
    public void activate(String authCode) throws CATokenOfflineException, CATokenAuthenticationFailedException {
        try {
            if ( keyStore==null ) {
                keyStore = getKeyStore(authCode);
            }
            setKeys(keyStore, authCode);
            log.debug("Keys from "+sSlotLabel+ " activated.");
        } catch( Throwable t ) {
            log.info("Authentication failed for keystore "+sSlotLabel+':', t );
            CATokenAuthenticationFailedException e = new CATokenAuthenticationFailedException(t.toString());
            e.initCause(t);
            try {
                deactivate();
            } catch (Exception e1) {
                log.error("Not possbile to deactivate token.", e1);
            }
            throw e;
        }
		String msg = intres.getLocalizedMessage("catoken.activated", "nFast");
        log.info(msg);
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.ICAToken#init(java.util.Properties, java.util.HashMap, java.lang.String, int)
     */
    public void init(Properties properties, HashMap data, String signaturealgorithm, int caid) throws Exception {
        setProviders(PROVIDER_CLASS, PROVIDER_CLASS_JCE);
        init(SLOT_LABEL_KEY, properties, signaturealgorithm, true);
    }
}
