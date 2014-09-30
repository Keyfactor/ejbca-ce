/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

/**
 * Thrown any time the key renewal process fails.
 * 
 * @version $Id$
 *
 */
public class KeyRenewalFailedException extends Exception {

    private static final long serialVersionUID = -7743705042076215320L;
    
    public KeyRenewalFailedException() {
        super();
    }

    public KeyRenewalFailedException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public KeyRenewalFailedException(String arg0) {
        super(arg0);
    }

    public KeyRenewalFailedException(Throwable arg0) {
        super(arg0);
    }



}
