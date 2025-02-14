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

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Provides an interface for Validators to be testable, primarily from the UI. 
 */
public interface TestableValidator {

    /**
     * 
     * @return an empty list in the case of success, or error messages if not. 
     */
    List<String> test(final X509Certificate testCertificate);

    
}
