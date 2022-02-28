/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.azure;

public class AzureException extends Exception {

    public AzureException(String message) {
        super(message);
    }
    public AzureException(String message, Throwable e) {
        super(message, e);
    }

}
