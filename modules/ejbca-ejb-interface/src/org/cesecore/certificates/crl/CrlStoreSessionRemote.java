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
 * Remote interface for CreateCRLSession
 * Based on EJBCA version: CrlSessionRemote.java 11122 2011-01-10 11:08:59Z anatom
 * 
 * @version $Id: CrlStoreSessionRemote.java 207 2011-01-31 13:36:36Z tomas $
 */
@Remote
public interface CrlStoreSessionRemote extends CrlStoreSession {

}
