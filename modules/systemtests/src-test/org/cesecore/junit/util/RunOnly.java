/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.junit.util;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Restricts CryptoTokenRunner to only running one implementation. 
 * 
 * @version $Id$
 *
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface RunOnly {
    /**
     * 
     * @return one of "pkcs11" or "pkcs12".  
     */
    String implementation();
}
