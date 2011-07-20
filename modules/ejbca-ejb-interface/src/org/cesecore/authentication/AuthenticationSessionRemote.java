/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authentication;

import javax.ejb.Remote;

/**
 * Remote interface for the Authentication session bean.
 * 
 * Based on cesecore version:
 *      AuthenticationSessionRemote.java 168 2011-01-27 10:07:30Z mikek
 * 
 * @version $Id$
 *
 */
@Remote
public interface AuthenticationSessionRemote extends AuthenticationSession {

}
