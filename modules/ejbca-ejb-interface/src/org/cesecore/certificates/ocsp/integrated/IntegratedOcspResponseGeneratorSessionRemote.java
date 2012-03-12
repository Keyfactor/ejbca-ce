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
package org.cesecore.certificates.ocsp.integrated;

import javax.ejb.Remote;

import org.cesecore.certificates.ocsp.OcspResponseGeneratorSession;

/**
 * Remote interface for OcspResponseGeneratorSession
 * 
 * @version $Id$
 *
 */
@Remote
public interface IntegratedOcspResponseGeneratorSessionRemote extends OcspResponseGeneratorSession {
   
}
