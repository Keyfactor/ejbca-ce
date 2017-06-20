/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

/**
 * Producer interface for public key blacklist access. All domain objects or services providing
 * public key blacklists must implement this interface.
 * 
 * @version $Id: PublicKeyBlacklistProducer.java 22117 2017-05-01 12:12:00Z anjakobs $
 */
public interface PublicKeyBlacklistProducer {

    PublicKeyBlacklist findByFingerprint(String fingerprint);
}
