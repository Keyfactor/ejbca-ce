/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.keys.rsa;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.ejbca.ssh.keys.SshKeyPair;

/**
 * SSH RSA Key Pair.
 *
 * @version $Id$
 */
public class SshRsaKeyPair implements SshKeyPair {

    private final SshRsaPublicKey rsaPublicKey;
    private final RSAPrivateKey rsaPrivateKey;

    public SshRsaKeyPair(int size) {
      KeyPair keyPair;
      try {
        keyPair = KeyTools.genKeys(Integer.toString(size), AlgorithmConstants.KEYALGORITHM_RSA);
      } catch (InvalidAlgorithmParameterException e) {
        throw new IllegalStateException("Could not create RSA keys of size " + size, e);
      }
      this.rsaPublicKey = new SshRsaPublicKey((RSAPublicKey)keyPair.getPublic());
      this.rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
    }

    @Override
    public SshRsaPublicKey getPublicKey() {
      return this.rsaPublicKey;
    }

    public PrivateKey getPrivateKey() {
      return this.rsaPrivateKey;
    }

    public void exportPublicKeyToFile(File file, String comment) throws IOException {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(this.rsaPublicKey.encodeForExport(comment));
            out.flush();
        }
    }
  }
