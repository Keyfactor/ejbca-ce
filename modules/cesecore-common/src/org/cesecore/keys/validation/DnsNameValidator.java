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

import java.util.List;

/**
 * Base interface for DNS name validators. All DNS name validators must implement this interface.
 * 
 * @version $Id$
 *
 */
public interface DnsNameValidator extends Validator {

    /**
     * Validates DNS names, specifically the dnsName value in the SubjectAltName (SAN) extension
     * 
     * @param domainNames an array of domain names 
     * 
     * @return the error messages or an empty list if all input was validated successfully 
     */
    List<String> validate(String ... domainNames);
    
    String getIssuer();
}
