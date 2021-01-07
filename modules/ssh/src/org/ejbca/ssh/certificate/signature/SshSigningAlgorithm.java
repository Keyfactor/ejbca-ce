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
 */

public interface SshSigningAlgorithm {

    /**
     * @return the common identifier for this signing algorithm
     */
    String getIdentifier();

    /**
     * @param provider signature provider, for example BouncyCastleProvider.PROVIDER_NAME for a software provider, or a PKCS#11 provider for signing using an HSM
     * @return a ready made Signer for this algorithm, using the specified provider 
     */
    Signature getSigner(final String provider);

    /**
     * @return the SSH specific prefix to be used when encoding the signature
     */
    String getPrefix();

}
