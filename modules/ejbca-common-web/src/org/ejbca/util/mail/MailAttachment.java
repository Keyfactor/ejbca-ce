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

package org.ejbca.util.mail;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import jakarta.activation.DataHandler;
import jakarta.mail.util.ByteArrayDataSource;

/**
 * Representation of an email attachment.
 */
public class MailAttachment {

	private ByteArrayDataSource dataSource;
	
	private String filename = "attachement";

	/**
     * Creates a mail attachment either by a ByteArrayDataSource or a java.security.cert.Certificate object.
     * 
     * @param attachedObject the object to be attached.
     * @param filename the attachment filename.
     */
    public MailAttachment(final Object attachedObject, final String filename) {
        this.filename = filename;
        if (attachedObject instanceof ByteArrayDataSource) {
            dataSource = (ByteArrayDataSource) attachedObject;
        } else if (attachedObject instanceof Certificate) {
            try {
                dataSource = new ByteArrayDataSource(((Certificate) attachedObject).getEncoded(), "application/pkix-cert");
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("The email attachment type is not supported.", e);
            }
        } else {
            throw new IllegalStateException("The email attachment type is not supported.");
        }
    }
    
    public String getName() {
        return filename;
    }

	public DataHandler getDataHandler() {
		if (dataSource != null) {
			return new DataHandler(dataSource);
		}
		return null;
	}
}
