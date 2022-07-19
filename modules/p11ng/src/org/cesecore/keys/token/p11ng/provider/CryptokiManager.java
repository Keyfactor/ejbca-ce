/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng.provider;

import java.security.Provider;
import java.security.Security;
import java.util.HashMap;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.jacknji11.ExtendedCryptokiE;
import org.cesecore.keys.token.p11ng.jacknji11.ExtendedCryptoki;
import org.cesecore.keys.token.p11ng.jacknji11.ExtendedJNA;
import org.cesecore.keys.token.p11ng.jacknji11.ExtendedJNANativeI;

/**
 * Singleton managing the various cryptoki devices available.
 */
public class CryptokiManager {

    private static final Logger LOG = Logger.getLogger(CryptokiManager.class);

    private static final CryptokiManager INSTANCE = new CryptokiManager();

    private final HashMap<String, CryptokiDevice> devices = new HashMap<>();

    public static CryptokiManager getInstance() {
        return INSTANCE;
    }

    private CryptokiManager() {}

    public synchronized CryptokiDevice getDevice(final String libName, final String libDir, final boolean withCache) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">getDevice(" + libName + ", " + libDir + ", " + withCache + ")");
        }
        CryptokiDevice result = devices.get(getId(libName, libDir));
        if (result == null) {
            NativeLibrary.addSearchPath(libName, libDir);
            final ExtendedJNANativeI jnaiNative = (ExtendedJNANativeI) Native.loadLibrary(libName, ExtendedJNANativeI.class);
            final ExtendedCryptokiE ce = new ExtendedCryptokiE(new ExtendedCryptoki(new ExtendedJNA(jnaiNative)));
            result = new CryptokiDevice(ce, withCache, getInstallOrReInstallProvider(), libName);
            devices.put(getId(libName, libDir), result);
        }
        return result;
    }

    private JackNJI11Provider getInstallOrReInstallProvider() {
        final JackNJI11Provider result;
        Provider p = Security.getProvider(JackNJI11Provider.NAME);
        if (p instanceof JackNJI11Provider) {
            result = (JackNJI11Provider) p;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using existing provider");
            }
        } else if (p != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found old provider. Re-installing.");
            }
            Security.removeProvider(JackNJI11Provider.NAME);
            result = new JackNJI11Provider();
            Security.addProvider(result);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Did not find our provider: " + p);
            }
            result = new JackNJI11Provider();
            Security.addProvider(result);
        }
        return result;
    }

    private static String getId(final String name, final String libDir) {
        return name + "@" + libDir;
    }
}
