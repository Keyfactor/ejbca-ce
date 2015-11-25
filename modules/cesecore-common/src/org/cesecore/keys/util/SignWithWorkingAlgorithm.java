/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.util;

import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;

/**
 * Call {@link #doIt(List, Provider, Operation)} or {@link #doIt(List, String, Operation)}
 * when you want to sign with any working algorithm in the list.
 * This is usable when working with HSMs. Different HSMs may support different
 * algorithms. Use this class when you just want to sign with any algorithm
 * supported by the HSM. Example of this:
 * - Signing of certificate to be used for the p11 certificate object corresponding
 *   to the p11 key.
 * - Signing of CSR when no particular algorithm is required by the receiver.
 * - Test signing, just checking that the key is working.
 * @version $Id$
 *
 */
public class SignWithWorkingAlgorithm<E extends Exception> {
    /** Log4j instance */
    private static final Logger log = Logger.getLogger(SignWithWorkingAlgorithm.class);
    final private static Map<Integer, String> signAlgorithmMap = new HashMap<>();
    final private static Map<Integer, SignWithWorkingAlgorithm<?>> instanceMap = new HashMap<>();
    final private Lock lock;
    final private Integer mapKey;

    /**
     * An object of a class implementing this interface must be constructed
     * before using {@link SignWithWorkingAlgorithm}.
     *
     */
    public interface Operation<E extends Exception> {
        /**
         * This method must implement the signing.
         * The method is called for each algorithm in the list passed to
         * {@link SignWithWorkingAlgorithm#doIt(List, Provider, Operation)}
         * until a working one is found.
         * @param signAlgorithm
         * @param provider
         * @throws E
         */
        public void doIt(String signAlgorithm, Provider provider) throws E;
    }

    /**
     * Finds the registered provider from sProvider and calls {@link #doIt(List, Provider, Operation)}.
     * @param availableSignAlgorithms algorithms to choose from.
     * @param sProvider provider name
     * @param operation operation the performs the signing
     * @return true if the signing was done.
     * @throws E exception thrown by {@link Operation#doIt(String, Provider)}
     * @throws NoSuchProviderException if the provider is not found.
     */
    public static <E extends Exception>boolean doIt(
            final List<String> availableSignAlgorithms,
            final String sProvider,
            final Operation<E> operation) throws E, NoSuchProviderException {
        final Provider provider = Security.getProvider(sProvider);
        if ( provider==null ) {
            throw new NoSuchProviderException();
        }
        return doIt(availableSignAlgorithms, provider, operation);
    }
    /**
     * First time each algorithm in availableSignAlgorithms are tried until the 
     * {@link Operation#doIt(String, Provider) is successfully completed.
     * The working algorithm is saved after the first time. Succeeding calls
     * with same availableSignAlgorithms and provider will directly use the 
     * algorithm that was working the first time.
     * @param availableSignAlgorithms algorithms to choose from.
     * @param provider
     * @param operation operation the performs the signing
     * @return true if the signing was done.
     * @throws E
     */
    public static <E extends Exception>boolean doIt(
            final List<String> availableSignAlgorithms,
            final Provider provider,
            final Operation<E> operation) throws E {
        final Integer mapKey = new Integer(availableSignAlgorithms.hashCode()^provider.hashCode());
        {
            final String signAlgorithm = signAlgorithmMap.get(mapKey);
            if ( signAlgorithm!=null ) {
                operation.doIt(signAlgorithm, provider);
                return true;
            }
        }
        final SignWithWorkingAlgorithm<E> instance;
        synchronized (instanceMap) {
            @SuppressWarnings("unchecked")
            final SignWithWorkingAlgorithm<E> waitInstance = (SignWithWorkingAlgorithm<E>)instanceMap.get(mapKey);
            if ( waitInstance==null ) {
                instance = new SignWithWorkingAlgorithm<>(mapKey);
                instanceMap.put(mapKey, instance);
            } else {
                instance = waitInstance;
            }
        }
        return instance.tryOutWorkingAlgorithm(availableSignAlgorithms, provider, operation);
    }
    private SignWithWorkingAlgorithm(final Integer _mapKey) {
        this.mapKey = _mapKey;
        this.lock = new ReentrantLock();
    }
    private boolean tryOutWorkingAlgorithm(
            final List<String> availableSignAlgorithms,
            final Provider provider,
            final Operation<E> operation) throws E{
        this.lock.lock();
        try {
            {
                final String signAlgorithm= signAlgorithmMap.get(this.mapKey);
                if ( signAlgorithm!=null ) {
                    operation.doIt(signAlgorithm, provider);
                    instanceMap.remove(this.mapKey);
                    return true;
                }
            }
            for ( final String signAlgorithm : availableSignAlgorithms ) {
                try {
                    operation.doIt(signAlgorithm, provider);
                } catch( final Exception e ) {
                    log.info(String.format("Signature algorithm '%s' not working for provider '%s'. Exception: %s", signAlgorithm, provider, e.getMessage()));
                    continue;
                }
                log.info(String.format("Signature algorithm '%s' working for provider '%s'.", signAlgorithm, provider));
                signAlgorithmMap.put(this.mapKey, signAlgorithm);
                instanceMap.remove(this.mapKey);
                return true;
            }
            log.info(String.format("No valid signing algorithm found for the provider '%s'.",  provider));
            return false;
        } finally {
            this.lock.unlock();
        }
    }
}
