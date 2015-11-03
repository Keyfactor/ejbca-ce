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

package org.ejbca.core.protocol.cmp.authentication;

import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * Interface for authentication modules of CMP Messages
 * 
 * @version $Id$
 *
 */
public interface ICMPAuthenticationModule {

    /**
     * Verifies that msg was sent by a trusted source.
     * 
     * @param msg PKIMessage to verify
     * @param username that the PKIMessage should match or null
     * @return true if msg was sent by a trusted source, and false otherwise
     */
    boolean verifyOrExtract(PKIMessage msg, String username);
    
    /**
     * Returns the name of the used authentication module.
     * 
     * @return the name of the used authentication module.
     */
    String getName();
    
    /**
     * Returns the password that was successfully used to authenticate the message.
     * 
     * This password is set if verifyOrExtract() returns true.
     * 
     * @return the password that was successfully used to authenticate the message. Null if the authentication had failed.
     */
    String getAuthenticationString();
    
    /**
     * Returns the error message resulted in failing to authenticate the message.
     * 
     * The error message should be set if verifyOrExtract() returns false.
     * 
     * @return The error message as String. Null if no error had occurred
     */
    String getErrorMessage();
}
