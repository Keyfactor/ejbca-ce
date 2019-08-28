/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or*
 *  modify it under the terms of the GNU Lesser General Public    *
 *  License as published by the Free Software Foundation; either  *
 *  version 2.1 of the License, or any later version.               *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.p11ngcli;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.cesecore.keys.token.p11ng.provider.GeneratedKeyData;
import org.cesecore.keys.token.p11ng.provider.JackNJI11Provider;


/**
 * 
 * @version $Id$
 *
 */
public class UnwrapThread extends OperationsThread {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(UnwrapThread.class);
    
    private final int id;
    private final String alias;
    private final String libName;
    private final String libDir;
    private final long slotId;
    private final String pin;
    private final int warmupTime;
    private final int timeLimit;
    private final String signatureAlgorithm;
    private final GeneratedKeyData wrappedKey;
    private final long wrappingCipher;
    private final boolean useCache;

    public UnwrapThread(final int id,
                          final FailureCallback failureCallback,
                          final String alias,
                          final String libName, final String libDir,
                          final long slotId, final String pin,
                          final int warmupTime, final int timeLimit,
                          final String signatureAlgorithm,
                          final GeneratedKeyData wrappedKey,
                          final long wrappingCipher,
                          final boolean useCache) {
        super(failureCallback);
        this.id = id;
        this.alias = alias;
        this.libName = libName;
        this.libDir = libDir;
        this.slotId = slotId;
        this.pin = pin;
        this.warmupTime = warmupTime;
        this.timeLimit = timeLimit;
        this.signatureAlgorithm = signatureAlgorithm;
        this.wrappedKey = wrappedKey;
        this.wrappingCipher = wrappingCipher;
        this.useCache = useCache;
    }
    
    @Override
    public void run() {
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        final CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(pin);
        final JackNJI11Provider provider = slot.getProvider();

        LOG.info("Starting thread " + id);
        
        final long startTime = System.currentTimeMillis();
        final long stopTime =
                timeLimit > 0 ? startTime + timeLimit : Long.MAX_VALUE;
        final long startCountingTime = startTime + warmupTime;

        slot.setUseCache(useCache);
        
        PrivateKey privKey = null;
        
        try {
            while (!isStop()) {
                privKey = slot.unwrapPrivateKey(wrappedKey.getWrappedPrivateKey(), alias,
                                                wrappingCipher);
                final Signature sign = Signature.getInstance(signatureAlgorithm, provider);

                sign.initSign(privKey);
                sign.update("Some data to be signed".getBytes("UTF-8"));
                byte[] signature = sign.sign();

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signing in thread " + id);
                    LOG.debug("Signature: " + new String(Base64.encode(signature)));
                }

                final long currTime = System.currentTimeMillis();

                if (currTime > stopTime) {
                    break;
                }

                if (currTime >= startCountingTime) {
                    registerOperation();
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                 UnsupportedEncodingException | SignatureException | RuntimeException e) {
            LOG.error("Failing signing: " + e.getMessage());
            fireFailure(getName() + ": failed after " + getNumberOfOperations() + " signings: " + e.getMessage());
        } finally {
            if (privKey != null) {
                slot.releasePrivateKey(privKey);
            }
        }
    }
}
