/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.msae;

/**
 *
 */
public class EnrollmentException extends Exception
{
	private static final long serialVersionUID = 5836428964136524766L;

	public EnrollmentException(String string) {
        super(string);
    }
}
