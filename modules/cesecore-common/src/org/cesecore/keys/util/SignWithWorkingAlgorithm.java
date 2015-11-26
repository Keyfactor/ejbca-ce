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
public class SignWithWorkingAlgorithm {
    /** Log4j instance */
    final private static Logger log = Logger.getLogger(SignWithWorkingAlgorithm.class);
    final private static Map<Integer, SignWithWorkingAlgorithm> instanceMap = new HashMap<>();
    final private Provider provider;
    final private List<String> availableSignAlgorithms;
    private String signAlgorithm;
    final private Lock lock;

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
        final SignWithWorkingAlgorithm instance;
        synchronized (instanceMap) {
            final SignWithWorkingAlgorithm waitInstance = instanceMap.get(mapKey);
            if ( waitInstance==null ) {
                instance = new SignWithWorkingAlgorithm(provider, availableSignAlgorithms);
                instanceMap.put(mapKey, instance);
            } else {
                instance = waitInstance;
            }
        }
        return instance.doIt(operation);
    }
    private SignWithWorkingAlgorithm(
            final Provider _provider,
            final List<String> _availableSignAlgorithms) {
        this.provider = _provider;
        this.lock = new ReentrantLock();
        this.availableSignAlgorithms = _availableSignAlgorithms;
    }
    private <E extends Exception>boolean doIt(final Operation<E> operation) throws E {
        if ( this.signAlgorithm!=null ) {
            operation.doIt(this.signAlgorithm, this.provider);
            return true;
        }
        this.lock.lock();
        try {
            if ( this.signAlgorithm!=null ) {
                operation.doIt(this.signAlgorithm, this.provider);
                // If we get a problem that some keys don't work with the selected
                // provider we may:
                // 1. catch the exception her
                // 2. this.signAlgorithm = null;
                // 3. Throw the caught exception again
                // But it will be batter to avoid this by other mean.
                // For example to order the list after hash length with the shortest
                // first.
                return true;
            }
            for ( final String trySignAlgorithm : this.availableSignAlgorithms ) {
                try {
                    operation.doIt(trySignAlgorithm, this.provider);
                } catch( final Exception e ) {
                    log.info(String.format("Signature algorithm '%s' not working for provider '%s'. Exception: %s", trySignAlgorithm, this.provider, e.getMessage()));
                    continue;
                }
                log.info(String.format("Signature algorithm '%s' working for provider '%s'.", trySignAlgorithm, this.provider));
                this.signAlgorithm = trySignAlgorithm;
                return true;
            }
            log.info(String.format("No valid signing algorithm found for the provider '%s'.",  this.provider));
            return false;
        } finally {
            this.lock.unlock();
        }
    }
}
