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

package org.ejbca.core.protocol.xkms.client;

/**
 * Exception throws in a XKMS service signature
 * cannot be verified.
 * 
 * 
 * @author Philip Vendil 2006 dec 20
 *
 * @version $Id$
 */

public class XKMSResponseSignatureException extends Exception {

	private static final long serialVersionUID = -5168081159971575912L;

    public XKMSResponseSignatureException() {
		super();
	}

	public XKMSResponseSignatureException(String arg0, Throwable arg1) {
		super(arg0, arg1);
	}

	public XKMSResponseSignatureException(String arg0) {
		super(arg0);
	}

	public XKMSResponseSignatureException(Throwable arg0) {
		super(arg0);
	}

}
