package org.cesecore.certificates.util;

import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;

public class SignWithWorkingAlgorithm {
    /** Log4j instance */
    private static final Logger log = Logger.getLogger(AlgorithmTools.class);
    public interface Operation {
        public void doIt(String signAlgorithm, Provider provider) throws Exception;
    }
    final private static Map<Integer, String> signAlgorithmMap = new HashMap<>();
    final private static Map<Integer, SignWithWorkingAlgorithm> providerMap = new HashMap<>();

    public static boolean doIt(
            final List<String> availableSignAlgorithms,
            final String sProvider,
            final Operation operation) throws Exception {
        final Provider provider = Security.getProvider(sProvider);
        if ( provider==null ) {
            throw new NoSuchProviderException();
        }
        return doIt(availableSignAlgorithms, provider, operation);
    }
    public static boolean doIt(
            final List<String> availableSignAlgorithms,
            final Provider provider,
            final Operation operation) throws Exception {
        final Integer mapKey = new Integer(availableSignAlgorithms.hashCode()^provider.hashCode());
        {
            final String signAlgorithm = signAlgorithmMap.get(mapKey);
            if ( signAlgorithm!=null ) {
                operation.doIt(signAlgorithm, provider);
                return true;
            }
        }
        final SignWithWorkingAlgorithm instance;
        synchronized (providerMap) {
            final SignWithWorkingAlgorithm waitInstance = providerMap.get(mapKey);
            if ( waitInstance==null ) {
                instance = new SignWithWorkingAlgorithm(mapKey);
                providerMap.put(mapKey, instance);
            } else {
                instance = waitInstance;
            }
        }
        return instance.tryOutWorkingAlgorithm(availableSignAlgorithms, provider, operation);
    }
    final private Lock lock;
    final private Integer mapKey;
    private SignWithWorkingAlgorithm(final Integer _mapKey) {
        this.mapKey = _mapKey;
        this.lock = new ReentrantLock();
    }
    private boolean tryOutWorkingAlgorithm(
            final List<String> availableSignAlgorithms,
            final Provider provider,
            final Operation operation) throws Exception{
        this.lock.lock();
        {
            final String signAlgorithm;
            try {
                signAlgorithm= signAlgorithmMap.get(this.mapKey);
            } catch( Throwable e) {
                this.lock.unlock();
                throw e;
            }
            if ( signAlgorithm!=null ) {
                this.lock.unlock();
                operation.doIt(signAlgorithm, provider);
                providerMap.remove(this.mapKey);
                return true;
            }
        }
        try {
            for ( final String signAlgorithm : availableSignAlgorithms ) {
                try {
                    operation.doIt(signAlgorithm, provider);
                } catch( final Exception e ) {
                    log.info(String.format("Signature algorithm '%s' not working for provider '%s'. Exception: %s", signAlgorithm, provider, e.getMessage()));
                    continue;
                }
                log.info(String.format("Signature algorithm '%s' working for provider '%s'.", signAlgorithm, provider));
                signAlgorithmMap.put(this.mapKey, signAlgorithm);
                providerMap.remove(this.mapKey);
                return true;
            }
            return false;
        } finally {
            this.lock.unlock();
        }
    }
}
