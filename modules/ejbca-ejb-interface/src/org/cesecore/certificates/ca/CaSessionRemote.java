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
package org.cesecore.certificates.ca;

import javax.ejb.Remote;

/**
 * Remote interface for CaSession
 * 
 * Based on EJBCA version: CaSessionRemote.java 10428 2010-11-11 16:45:12Z anatom
 * 
 * @version $Id: CaSessionRemote.java 124 2011-01-20 14:41:21Z tomas $
 */
@Remote
public interface CaSessionRemote extends CaSession {

}
