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

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.security.cert.Certificate;
import javax.security.cert.CertificateEncodingException;

/**
 * Representation of an email attachment.
 * 
 * @version $Id$
 */
public class MailAttachment {

	private String filename;
	private String fullFilePathName;
	
	public MailAttachment(String fullFilePathName) {
		this.filename = new File(fullFilePathName).getName();
	}

	public MailAttachment(String filename, String fullFilePathName) {
		this.filename = filename;
		this.fullFilePathName = fullFilePathName;
	}

	/**
	 * Write's the object to a temporary file that is then attached.
	 * TODO: In later versions of JavaMail we can use ByteArrayDataSource directly in getDataHandler instead.
	 * 
	 * @param filename
	 * @param attachedObject
	 */
	public MailAttachment(String filename, Object attachedObject) {
		this.filename = filename;
		try {
			byte[] attachmentData;
			if (attachedObject instanceof Certificate) {
				try {
					attachmentData = ((Certificate)attachedObject).getEncoded();
				} catch (CertificateEncodingException e) {
					throw new IllegalStateException("The email attachment type is not supported.", e);
				}
			} else {
				throw new IllegalStateException("The email attachment type is not supported.");
			}
			File file = File.createTempFile("ejbca-mailattachment", ".tmp");
			fullFilePathName = file.getCanonicalPath();
			try (
			        FileOutputStream fos = new FileOutputStream(file);
			        DataOutputStream dos = new DataOutputStream (fos);
			        ) {
			dos.write(attachmentData);
			}
		} catch (IOException e) {
			throw new IllegalStateException("The email attachment type is not supported.", e);
		}
	}
	
	public String getName() {
		return filename;
	}

	public DataHandler getDataHandler() {
		if (fullFilePathName != null) {
			return new DataHandler(new FileDataSource(getName()));
		}
		return null;
	}
}
