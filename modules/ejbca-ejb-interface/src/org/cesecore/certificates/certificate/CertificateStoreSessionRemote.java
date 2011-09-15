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
package org.cesecore.certificates.certificate;

import javax.ejb.Remote;

/**
 * Remote interface for CertificateStoreSession.
 * Based on EJBCA version: CertificateStoreSessionRemote.java 11278 2011-01-28 14:06:19Z anatom
 * 
 * @version $Id$
 */
@Remote
public interface CertificateStoreSessionRemote extends CertificateStoreSession {

}
