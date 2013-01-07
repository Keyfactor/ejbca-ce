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
package org.cesecore.certificates.ocsp.integrated;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.ocsp.OcspResponseSessionBean;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.cache.TokenAndChainCache;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.util.log.SaferAppenderListener;
import org.cesecore.util.log.SaferDailyRollingFileAppender;

/**
 * 
 * This class is based on OCSPUtil.java 11154 2011-01-12 09:56:23Z jeklund and OCSPServletBase.java 11143 2011-01-11 15:32:31Z jeklund
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "IntegratedOcspResponseGeneratorSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class IntegratedOcspResponseGeneratorSessionBean extends OcspResponseSessionBean implements
        IntegratedOcspResponseGeneratorSessionRemote, IntegratedOcspResponseGeneratorSessionLocal, SaferAppenderListener {

    private static final Logger log = Logger.getLogger(IntegratedOcspResponseGeneratorSessionBean.class);

    private static final String INTERNAL_ADMIN_PRINCIPAL = "Integrated OCSP cache update";

    /** 
     * 
     * This class member knowingly breaks the EJB standard which forbids static volatile class members. The
     * spirit of this rule is to prohibit implementations from using mutexes in their SSBs, thus negating the
     * EJB bean pool. It doesn't take into account the need to cache data in a shared singleton, thus we have 
     * to knowingly break the standard, but not its spirit. 
     * 
     */
    private static volatile TokenAndChainCache cache;

    @Resource
    private SessionContext sessionContext;
    /* When the sessionContext is injected, the timerService should be looked up.
     * This is due to the Glassfish EJB verifier complaining. 
     */
    private TimerService timerService;

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;

    @PostConstruct
    public void init() throws AuthorizationDeniedException {
        if (OcspConfiguration.getLogSafer() == true) {
            SaferDailyRollingFileAppender.addSubscriber(this);
            log.info("added us as subscriber" + SaferDailyRollingFileAppender.class.getCanonicalName());
        }

        timerService = sessionContext.getTimerService();

        if (cache == null) {
            cache = new TokenAndChainCache();
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void reloadTokenAndChainCache() {
    	// Cancel any waiting timers
    	cancelTimers();
    	try {
    		Map<Integer, CryptoTokenAndChain> newCache = new ConcurrentHashMap<Integer, CryptoTokenAndChain>();
    		for (Integer caId : caSession.getAvailableCAs()) {
    			CA ca = null;
    			try {
    			    AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(INTERNAL_ADMIN_PRINCIPAL));
    				ca = caSession.getCA(authenticationToken, caId);
    			} catch (CADoesntExistsException e) {
    				// Should not be able to happen.
    				throw new Error("Could not find CA with id " + caId + " in spite of value just being collected from database.");
    			} catch (AuthorizationDeniedException e) {
    			    //Likewise
    			    throw new Error("AlwaysAllowLocalAuthenticationToken was denied access.");
    			}
                if (ca.getCAType() == CAInfo.CATYPE_CVC || ca.getCACertificate()==null) {
                    // Bravely ignore OCSP for CVC CAs or CA's that have no CA certificate (yet)
                    continue;
                }
    			CertificateID certId = null;
    			try {
    				certId = new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), (X509Certificate) ca.getCACertificate(), new BigInteger("1"));
    			} catch (OCSPException e) {
    				throw new OcspFailureException(e);
    			} catch(CertificateEncodingException e) {
    			    throw new OcspFailureException(e);
    			}
    			final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
    			if (cryptoToken==null) {
    	            log.error("Crypto token retrieved from CA was invalid. This is an erronous state.");
    			} else {
                    newCache.put(TokenAndChainCache.keyFromCertificateID(certId), new CryptoTokenAndChain(cryptoToken, ca
                            .getCertificateChain().toArray(new X509Certificate[ca.getCertificateChain().size()]), CAToken.SOFTPRIVATESIGNKEYALIAS));
    			}
    		}
    		try {
    			X509Certificate latestCertificate = certificateStoreSession.findLatestX509CertificateBySubject(OcspConfiguration.getDefaultResponderId());

    			if (latestCertificate == null) {
    				log.warn("Could not find default responder in database.");
    				cache.updateCache(newCache, null);
    			} else {
    				cache.updateCache(newCache, new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), latestCertificate, new BigInteger("1")));
    			}
    		} catch (OCSPException e) {
    			throw new OcspFailureException(e);
    		} catch(CertificateEncodingException e) {
    		    throw new OcspFailureException(e);
    		}
    	} finally {
    		// Schedule a new timer
    		addTimer(OcspConfiguration.getSignTrustValidTimeInSeconds(), cache.hashCode());
    	}
    }

    protected void initiateIfNecessary() {
        if (timerService.getTimers().size() == 0) {
            reloadTokenAndChainCache(); 
        }
    }

    /**
     * When a timer expires, this method will update
     * 
     * According to JSR 220 FR (18.2.2), this method may not throw any exceptions.
     * 
     * @param timer The timer whose expiration caused this notification.
     * 
     */
    @Timeout
    /* Glassfish 2.1.1:
     * "Timeout method ....timeoutHandler(javax.ejb.Timer)must have TX attribute of TX_REQUIRES_NEW or TX_REQUIRED or TX_NOT_SUPPORTED"
     * JBoss 5.1.0.GA: We cannot mix timer updates with our EJBCA DataSource transactions. 
     */
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(Timer timer) {
    	if (log.isTraceEnabled()) {
    		log.trace(">timeoutHandler: "+timer.getInfo().toString()+", "+timer.getNextTimeout().toString());
    	}

        // reloadTokenAndChainCache cancels old timers and adds a new timer
        reloadTokenAndChainCache();
   
    	if (log.isTraceEnabled()) {
    		log.trace("<timeoutHandler");
    	}
    }

    /**
     * This method cancels all timers associated with this bean.
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    public void cancelTimers() {
        if (log.isTraceEnabled()) {
        	log.trace(">cancelTimers");
        }
        @SuppressWarnings("unchecked")
        Collection<Timer> timers = timerService.getTimers();
        for (Timer timer : timers) {
            timer.cancel();
        }
        if (log.isTraceEnabled()) {
        	log.trace("<cancelTimers, timers canceled: "+timers.size());
        }
    }

    /**
     * Adds a timer to the bean
     * 
     * @param id the id of the timer
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    public Timer addTimer(long interval, Integer id) {
        if (log.isTraceEnabled()) {
            log.trace(">addTimer: " + id+", interval: "+interval);
        }
        Timer ret = timerService.createTimer(interval, id);
        if (log.isTraceEnabled()) {
            log.trace("<addTimer: " + id+", interval: "+interval+", "+ret.getNextTimeout().toString());
        }
        return ret;
    }

    @Override
    protected TokenAndChainCache getTokenAndChainCache() {
        return cache;
    }

}
