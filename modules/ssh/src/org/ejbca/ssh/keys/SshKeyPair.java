/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.keys;

import java.security.PrivateKey;

import org.cesecore.certificates.certificate.ssh.SshPublicKey;

/**
 * SSH Key Pair.
 *
 * @version $Id$
 */
public interface SshKeyPair {
    SshPublicKey getPublicKey();

    PrivateKey getPrivateKey();
  }
