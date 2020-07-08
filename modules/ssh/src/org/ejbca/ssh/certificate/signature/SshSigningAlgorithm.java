/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.certificate.signature;

import java.security.Signature;

/**
 * Interface for SSH Signing Algorithm enums
 *
 * @version $Id$
 */

public interface SshSigningAlgorithm {

    /**
     * @return the common identifier for this signing algorithm
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
