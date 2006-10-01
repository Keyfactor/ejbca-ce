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
package org.ejbca.core.model.services;

/**
 * Exception generated if a IAction.performAction calls failed.
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id: ActionException.java,v 1.1 2006-10-01 17:44:45 herrvendil Exp $
 */
public class ActionException extends Exception {

	/**
	 * Exception generated if a IAction.performAction calls failed
	 * @param message
	 * @param cause
	 */
	public ActionException(String message, Throwable cause) {
		super(message, cause);		
	}

	/**
	 * Exception generated if a IAction.performAction calls failed
	 * @param message
	 */
	public ActionException(String message) {
		super(message);
	}

}
