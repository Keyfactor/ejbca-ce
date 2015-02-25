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
package org.cesecore.certificates.certificateprofile;

import java.util.Map;

import javax.ejb.Local;

/**
 * @version $Id$
 */
@Local
public interface CertificateProfileSessionLocal extends CertificateProfileSession {

    /**
     * 
     * @return a collection of all existing certificate profiles.
     */
    Map<Integer, CertificateProfile> getAllCertificateProfiles();
    
}
