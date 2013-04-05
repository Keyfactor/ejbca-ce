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
package org.ejbca.core.ejb.certificates.crl;

import javax.ejb.Remote;

import org.cesecore.certificates.crl.CrlCreateSessionRemote;

/**
 * Remote interface for CrlCreateSession in EJBCA.
 * 
 * Overrides the interface from CESeCore in order to lookup/inject the 
 * EJBCA implementation with added functionality (ie. publishing).
 * 
 * @version $Id: CrlCreateSessionRemote.java 16152 2013-01-20 15:44:17Z anatom $
 *
 */
@Remote
public interface EjbcaCrlCreateSessionRemote extends CrlCreateSessionRemote {

}
