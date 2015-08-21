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
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.ui.web.admin.configuration.InformationMemory;

/**
 * A class handling the hardtoken profile data in the webinterface.
 *
 * @version $Id$
 */
public class PublisherDataHandler implements Serializable {

    private static final long serialVersionUID = -5646053740072121787L;

    private PublisherSessionLocal publishersession;
    private CAAdminSession caadminsession;
    private CertificateProfileSession certificateProfileSession;
    private AuthenticationToken administrator;
    private InformationMemory info;

    /** Creates a new instance of PublisherDataHandler */
    public PublisherDataHandler(AuthenticationToken administrator, PublisherSessionLocal publishersession, CAAdminSession caadminsession,
            CertificateProfileSession certificateProfileSession, InformationMemory info) {
        this.publishersession = publishersession;
        this.caadminsession = caadminsession;
        this.certificateProfileSession = certificateProfileSession;
        this.administrator = administrator;
        this.info = info;
    }

    /** Method to add a publisher. Throws PublisherExitsException if profile already exists  */
    public void addPublisher(String name, BasePublisher publisher) throws PublisherExistsException, AuthorizationDeniedException {
        publishersession.addPublisher(administrator, name, publisher);
        this.info.publishersEdited();

    }

    /** Method to change a publisher. */
    public void changePublisher(String name, BasePublisher publisher) throws AuthorizationDeniedException {
        publishersession.changePublisher(administrator, name, publisher);
        this.info.publishersEdited();
    }

    /** Method to remove a publisher, returns true if deletion failed.*/
    public boolean removePublisher(String name) throws AuthorizationDeniedException {
        boolean returnval = true;

        int publisherid = publishersession.getPublisherId(name);
        if (!caadminsession.exitsPublisherInCAs(publisherid)
                && !certificateProfileSession.existsPublisherIdInCertificateProfiles(publisherid)) {
            publishersession.removePublisher(administrator, name);
            this.info.publishersEdited();
            returnval = false;
        }

        return returnval;
    }

    /** Metod to rename a publisher */
    public void renamePublisher(String oldname, String newname) throws PublisherExistsException, AuthorizationDeniedException {
        publishersession.renamePublisher(administrator, oldname, newname);
        this.info.publishersEdited();

    }

    public void clonePublisher(String originalname, String newname) throws AuthorizationDeniedException, PublisherDoesntExistsException,
            PublisherExistsException {
        publishersession.clonePublisher(administrator, originalname, newname);
        this.info.publishersEdited();
    }

    public void testConnection(String name) throws PublisherConnectionException {
        publishersession.testConnection(publishersession.getPublisherId(name));

    }

    /** Method to get a reference to a publisher. */
    public BasePublisher getPublisher(int id) {
        return publishersession.getPublisher(id);
    }

    public BasePublisher getPublisher(String name) {
        return publishersession.getPublisher(name);
    }

    public int getPublisherId(String name) {
        return publishersession.getPublisherId(name);
    }

}
