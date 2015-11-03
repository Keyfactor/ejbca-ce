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
package org.ejbca.core.model.services;

/**
 * Exception generated if a IAction.performAction calls failed.
 * 
 *
 * @version $Id$
 */
public class ActionException extends Exception {

	private static final long serialVersionUID = -2160550096301309104L;

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
