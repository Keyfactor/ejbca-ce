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

package org.ejbca.ssh.certificate.signature;

import java.security.Signature;

/**
 * Interface for SSH Signing Algorithm enums
 * 
 * @version $Id$
 *
 */

public interface SshSigningAlgorithm {

    /**
     * @return the commong identifier for this signing algorithm
     */
    String getIdentifier();

    /**
     * @return a ready made Signer for this algorithm
     */
    Signature getSigner();

    /**
     * @return the SSH specific prefix to be used when encoding the signature
     */
    String getPrefix();

}