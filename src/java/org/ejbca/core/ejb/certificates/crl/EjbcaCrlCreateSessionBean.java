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
package org.ejbca.core.ejb.certificates.crl;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CRLHolder;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.crl.CrlCreateSessionBean;
import org.cesecore.certificates.crl.CrlStoreException;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;

/**
 * Business class for CRL actions, i.e. running CRLs. CRUD operations can be found in CrlSession.
 * 
 * This class extends the CrlCreateSessionBean in CESeCore by adding storing using 
 * publishers available in EJBCA.
 * 
 * @version $Id: CrlCreateSessionBean.java 16158 2013-01-21 09:05:12Z anatom $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EjbcaCrlCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EjbcaCrlCreateSessionBean extends CrlCreateSessionBean implements EjbcaCrlCreateSessionLocal, EjbcaCrlCreateSessionRemote {

    private static final Logger log = Logger.getLogger(EjbcaCrlCreateSessionBean.class);
    /** Internal localization of logs and errors */

    @EJB
    private PublisherSessionLocal publisherSession;

    
    /**
     * Override the CRL storing in CESeCore also adding storing using 
     * publishers in EJBCA. 
     */
    @Override
    protected void storeCRL(final AuthenticationToken admin, final CA ca, final String cafp, final X509CRLHolder crl, final byte[] crlBytes, final int nextCrlNumber, final boolean deltaCRL)
            throws CrlStoreException, AuthorizationDeniedException, CesecoreException {
        // First let CESeCore do the normal storing
        super.storeCRL(admin, ca, cafp, crl, crlBytes, nextCrlNumber, deltaCRL);
        
        // In EJBCA we also let the publishers store the CRL
        if (log.isDebugEnabled()) {
            log.debug("Storing CRL in publishers");
        }
        this.publisherSession.storeCRL(admin, ca.getCRLPublishers(), crlBytes, cafp, nextCrlNumber, ca.getSubjectDN());        
    }    

}
