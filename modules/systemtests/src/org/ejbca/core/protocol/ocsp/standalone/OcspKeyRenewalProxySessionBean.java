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
package org.ejbca.core.protocol.ocsp.standalone;

import java.security.InvalidKeyException;
import java.security.KeyStoreException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.ocsp.OcspKeyRenewalSessionLocal;

/**
 * Proxy for making certain functions in OcspKeyRenewalSessionBean testable remotely.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspKeyRenewalProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class OcspKeyRenewalProxySessionBean implements OcspKeyRenewalProxySessionRemote, OcspKeyRenewalProxySessionLocal {

    private static final Logger log = Logger.getLogger(OcspKeyRenewalProxySessionBean.class);

    @EJB
    private OcspKeyRenewalSessionLocal ocspKeyRenewalSession; 
    
    @Override
    public void setTimerToFireInOneSecond() throws InterruptedException {
        log.debug(">setTimerToFireInOneSecond");    // debug level is ok, since it will never run in production
        long oldValue = OcspConfiguration.getRekeyingUpdateTimeInSeconds();
        ConfigurationHolder.updateConfiguration(OcspConfiguration.REKEYING_UPDATE_TIME_IN_SECONDS, "1");
        ConfigurationHolder.updateConfiguration(OcspConfiguration.REKEYING_SAFETY_MARGIN_IN_SECONDS, Long.toString(Long.MAX_VALUE/1000));
        try {
            ocspKeyRenewalSession.startTimer();
            //Sleep for a second before killing the timer. 
            Thread.sleep(1000);
        } finally {
            ConfigurationHolder.updateConfiguration(OcspConfiguration.REKEYING_UPDATE_TIME_IN_SECONDS, Long.toString(oldValue));
            ocspKeyRenewalSession.startTimer();
        }
        log.debug("<setTimerToFireInOneSecond");
    }

    @Override
    public void renewKeyStores(String signerSubjectDN) throws KeyStoreException, CryptoTokenOfflineException, InvalidKeyException {
        log.debug(">renewKeyStores invoked with signerSubjectDN '" + signerSubjectDN + "'.");    // debug level is ok, since it will never run in production
        ocspKeyRenewalSession.renewKeyStores(signerSubjectDN);
        log.debug("<renewKeyStores");
    }
}
