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
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;

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
     * @param executorService a thread pool facilitating parallel lookups
     * @param domainNames one or several domain names (Varargs)
     * @return an Entry where key is the final validation result, true or false, and the value is a list is messages corresponding to
     * domain names passed as varargs, messages can include both success and failure messages, one failure will result in the key returned being false.
     */
    Entry<Boolean, List<String>> validate(final ExecutorService executorService, String... domainNames);

    String getIssuer();
}
