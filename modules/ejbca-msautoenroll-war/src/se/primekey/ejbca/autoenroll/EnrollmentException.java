/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package se.primekey.ejbca.autoenroll;

/**
 * 
 * @version $Id$
 */
public class EnrollmentException extends Exception
{
    private static final long serialVersionUID = 1L;

    public EnrollmentException(String string)
    {
        super(string);
    }
}
