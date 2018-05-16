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

package org.ejbca.core.ejb.rest;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;


/**
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EjbcaRestHelperSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EjbcaRestHelperSessionBean implements EjbcaRestHelperSessionLocal, EjbcaRestHelperSessionRemote {

    private static final Logger log = Logger.getLogger(EjbcaRestHelperSessionBean.class);

    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    @EJB
    private WebAuthenticationProviderSessionLocal authenticationSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public AuthenticationToken getAdmin(final boolean allowNonAdmins, X509Certificate cert) throws AuthorizationDeniedException {
        final Set<X509Certificate> credentials = new HashSet<>();
        credentials.add(cert);
        final AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
        final AuthenticationToken admin = authenticationSession.authenticate(subject);
        
        if ((admin != null) && (!allowNonAdmins)) {
            if(!raMasterApiProxyBean.isAuthorizedNoLogging(admin, AccessRulesConstants.ROLE_ADMINISTRATOR)) {
                final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.ROLE_ADMINISTRATOR, null);
                throw new AuthorizationDeniedException(msg);
            }
        } else if (admin == null) {
            final String msg = intres.getLocalizedMessage("authentication.failed", "No admin authenticated for certificate with serialNumber " + 
                    CertTools.getSerialNumber(cert) + " and issuerDN '" + CertTools.getIssuerDN(cert)+"'.");
            throw new AuthorizationDeniedException(msg);
        }
        return admin;
    }
}