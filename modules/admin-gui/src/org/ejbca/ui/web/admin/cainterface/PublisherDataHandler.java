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

package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;

/**
 * A class handling the hardtoken profile data in the webinterface.
 * 
 * @deprecated since 6.12.0. Use PublisherSession directly instead
 *
 * @version $Id$
 */
@Deprecated
public class PublisherDataHandler implements Serializable {

    private static final long serialVersionUID = -5646053740072121787L;

    private PublisherSessionLocal publishersession;
    private AuthenticationToken administrator;

    /** Creates a new instance of PublisherDataHandler */
    public PublisherDataHandler(AuthenticationToken administrator, PublisherSessionLocal publishersession) {
        this.publishersession = publishersession;
        this.administrator = administrator;
    }

    /** Method to add a publisher. Throws PublisherExitsException if profile already exists  */
    public void addPublisher(String name, BasePublisher publisher) throws PublisherExistsException, AuthorizationDeniedException {
        publishersession.addPublisher(administrator, name, publisher);

    }

    /** Method to change a publisher. */
    public void changePublisher(String name, BasePublisher publisher) throws AuthorizationDeniedException {
        publishersession.changePublisher(administrator, name, publisher);
    }

    /**
     * Removes a publisher
     * @throws AuthorizationDeniedException if not authorized
     * @throws ReferencesToItemExistException if references exist.
     */
    public void removePublisher(String name) throws ReferencesToItemExistException, AuthorizationDeniedException {
        publishersession.removePublisher(administrator, name);
    }

    /** Metod to rename a publisher */
    public void renamePublisher(String oldname, String newname) throws PublisherExistsException, AuthorizationDeniedException {
        publishersession.renamePublisher(administrator, oldname, newname);

    }

    public void clonePublisher(String originalname, String newname) throws AuthorizationDeniedException, PublisherDoesntExistsException,
            PublisherExistsException {
        publishersession.clonePublisher(administrator, originalname, newname);
    }

    public void testConnection(String name) throws PublisherConnectionException {
        publishersession.testConnection(publishersession.getPublisherId(name));

    }
    public BasePublisher getPublisher(String name) {
        return publishersession.getPublisher(name);
    }

    public int getPublisherId(String name) {
        return publishersession.getPublisherId(name);
    }

}
