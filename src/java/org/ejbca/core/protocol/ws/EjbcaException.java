package org.ejbca.core.protocol.ws;

/**
 * WebService specific Exception with the same meaning as EjbcaException
 * Used becaus current EjbcaException isn't compatible with the Jboss 
 * webservice stack (messages isn't reconstructed propertly).
 * 
 * @author Philip Vendil
 *  $Id: EjbcaException.java,v 1.1 2006-09-17 23:00:26 herrvendil Exp $
 * @see org.ejbca.core.EjbcaException
 */
public class EjbcaException extends Exception {
	
	public EjbcaException(String message) {
		super(message);
	}

}
