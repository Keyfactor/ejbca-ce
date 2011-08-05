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
package org.cesecore.certificates.crl;

import javax.ejb.Remote;

/**
 * Remote interface for CrlCreateSession
 * 
 * Based on EJBCA version: CrlCreateSessionRemote.java 10401 2010-11-09 12:20:21Z anatom
 * @version $Id: CrlCreateSessionRemote.java 349 2011-02-25 16:06:32Z tomas $
 *
 */
@Remote
public interface CrlCreateSessionRemote extends CrlCreateSession {

}
