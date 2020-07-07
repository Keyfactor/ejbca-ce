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
