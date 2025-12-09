package org.jscep.client.inspect;

import java.security.cert.CertStore;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Concrete factory for generating new DefaultCertStoreInspector instances.
 */
public class DefaultCertStoreInspectorFactory implements
        CertStoreInspectorFactory {
    private static final Map<CertStore, CertStoreInspector> INSTANCES = Collections.synchronizedMap(new WeakHashMap<CertStore, CertStoreInspector>());

    /**
     * {@inheritDoc}
     */
    @Override
    public CertStoreInspector getInstance(final CertStore store) {
        CertStoreInspector instance = INSTANCES.get(store);
        if (instance != null) {
            return instance;
        }
        instance = new DefaultCertStoreInspector(store);
        INSTANCES.put(store, instance);

        return instance;
    }

}
