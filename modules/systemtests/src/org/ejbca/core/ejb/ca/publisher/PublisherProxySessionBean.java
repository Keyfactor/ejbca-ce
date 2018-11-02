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
package org.ejbca.core.ejb.ca.publisher;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;

/**
 * @version $Id$
 *
 */

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "PublisherProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherProxySessionBean implements PublisherProxySessionRemote {

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;


    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    
    @Override
    public int addPublisher(AuthenticationToken admin, String name, BasePublisher publisher) throws PublisherExistsException, AuthorizationDeniedException {
        return publisherSession.addPublisher(admin, name, publisher);
    }

    @Override
    public void clonePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherDoesntExistsException, AuthorizationDeniedException, PublisherExistsException {
        publisherSession.clonePublisher(admin, oldname, newname);
    }

    @Override
    public int getPublisherId(String name) {
        return publisherSession.getPublisherId(name);
    }

    @Override
    public String getPublisherName(int id) {
        return publisherSession.getPublisherName(id);
    }

    @Override
    public void removePublisherInternal(AuthenticationToken admin, String name) throws AuthorizationDeniedException {
       publisherSession.removePublisherInternal(admin, name);

    }

    @Override
    public void renamePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherExistsException, AuthorizationDeniedException {
        publisherSession.renamePublisher(admin, oldname, newname);

    }

    @Override
    public void testConnection(int publisherid) throws PublisherConnectionException {
        publisherSession.testConnection(publisherid);
    }

    @Override
    public void flushPublisherCache() {
        publisherSession.flushPublisherCache();
    }

    @Override
    public void internalChangePublisherNoFlushCache(String name, BasePublisher publisher) throws AuthorizationDeniedException {
        PublisherData htp = PublisherData.findByName(entityManager, name);
        if (htp != null) {
            htp.setPublisher(publisher);
        }
    }

    @Override
    public int adhocUpgradeTo6_3_1_1() {
        return publisherSession.adhocUpgradeTo6_3_1_1();
    }
    
}
