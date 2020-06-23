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
package org.ejbca.ssh.keys.ec;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.ejbca.ssh.keys.SshKeyPair;

/**
 * @version $Id$
 *
 */
public class SshEcKeyPair implements SshKeyPair {

    private final SshEcPublicKey sshEcPublicKey;
    private final ECPrivateKey ecPrivateKey;

    /**
     * Creates an EC keypair of the given curve
     * 
     * @param curveName one of nistp256, nistp384 or nistp521
     * @throws InvalidKeySpecException if the curve name was invalid
     */
    public SshEcKeyPair(final String curveName) throws InvalidKeySpecException {
        KeyPair keyPair;
        try {
            keyPair = KeyTools.genKeys(SshEcPublicKey.translateCurveName(curveName), AlgorithmConstants.KEYALGORITHM_EC);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Could not create EC keys with curve name  " + curveName, e);
        }
        this.sshEcPublicKey = new SshEcPublicKey((ECPublicKey) keyPair.getPublic());
        this.ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    }

    @Override
    public SshEcPublicKey getPublicKey() {
        return this.sshEcPublicKey;
    }

    public PrivateKey getPrivateKey() {
        return this.ecPrivateKey;
    }

    public void exportPublicKeyToFile(File file, String comment) throws IOException {
        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(sshEcPublicKey.encodeForExport(comment));
            out.flush();
        } finally {
            out.close();
        }
    }
}
