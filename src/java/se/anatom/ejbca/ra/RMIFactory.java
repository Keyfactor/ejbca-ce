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
 
package se.anatom.ejbca.ra;

/**
 * Implementations of this interface creates RMI objects to be used as an alternative way to access
 * ejbca.
 *
 * @version $Id: RMIFactory.java,v 1.7 2004-04-16 07:38:56 anatom Exp $
 */
public interface RMIFactory {
    /**
     * executes code that may be used to set up a RMI server.
     */
    void startConnection(String[] args) throws Exception;
}
