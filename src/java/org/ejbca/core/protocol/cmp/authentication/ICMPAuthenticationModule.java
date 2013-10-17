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
     * @param authenticated if the CMP message has already been authenticated in another way or not
     * @return true of msg was sent by a trusted source, and false otherwise
     * @throws CmpAuthenticationException 
     */
    public abstract boolean verifyOrExtract(PKIMessage msg, String username, boolean authenticated) throws CmpAuthenticationException;
    
    /**
     * Returns the name of the used authentication module.
     * 
     * @return the name of the used authentication module.
     */
    public abstract String getName();
    
    /**
     * Returns the password that was successfully used to authenticate the message.
     * 
     * This password is set if verify() returns true.
     * 
     * @return the password that was successfully used to authenticate the message. Null if the authentication had failed.
     */
    public abstract String getAuthenticationString();
    
}
