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
 * @author Daniel Horn, SiO2 Corp.
 * 
 * @version $Id$
*/
public class EnrollmentException extends Exception
{
    public EnrollmentException(String string)
    {
        super(string);
    }
}
