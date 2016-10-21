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
 * Call {@link #doSignTask(List, Provider, ISignOperation)} or {@link #doSignTask(List, String, ISignOperation)}
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
     * Finds the registered provider from sProvider and calls {@link #doSignTask(List, Provider, ISignOperation)}.
     * @param availableSignAlgorithms algorithms to choose from.
     * @param sProvider provider name
     * @param operation operation the performs the signing, is an instance of ISignOperation for example KeyTools.SignDataOperation
     * @return true if the signing was done.
     * @throws NoSuchProviderException if the provider is not found.
     * @throws TaskWithSigningException  thrown if {@link ISignOperation#taskWithSigning(String, Provider)} is failing.
     */
    public static boolean doSignTask(
            final List<String> availableSignAlgorithms,
            final String sProvider,
            final ISignOperation operation) throws NoSuchProviderException, TaskWithSigningException {
        final Provider provider = Security.getProvider(sProvider);
        if ( provider==null ) {
            throw new NoSuchProviderException();
        }
        return doSignTask(availableSignAlgorithms, provider, operation);
    }
    /**
     * First time each algorithm in availableSignAlgorithms are tried until the 
     * {@link ISignOperation#taskWithSigning(String, Provider) is successfully completed.
     * The working algorithm is saved after the first time. Succeeding calls
     * with same availableSignAlgorithms and provider will directly use the 
     * algorithm that was working the first time.
     * @param availableSignAlgorithms algorithms to choose from.
     * @param provider
     * @param operation operation that performs the signing
     * @return true if the signing was done.
     * @throws TaskWithSigningException thrown if {@link ISignOperation#taskWithSigning(String, Provider)} is failing.
     */
    public static boolean doSignTask(
            final List<String> availableSignAlgorithms,
            final Provider provider,
            final ISignOperation operation) throws TaskWithSigningException {
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
        return instance.tryOutWorkingAlgorithm(operation);
    }
    private SignWithWorkingAlgorithm(
            final Provider _provider,
            final List<String> _availableSignAlgorithms) {
        this.provider = _provider;
        this.lock = new ReentrantLock();
        this.availableSignAlgorithms = _availableSignAlgorithms;
    }
    private boolean tryOutWorkingAlgorithm(final ISignOperation operation) throws TaskWithSigningException {
        if ( this.signAlgorithm!=null ) {
            operation.taskWithSigning(this.signAlgorithm, this.provider);
            return true;
        }
        this.lock.lock();
        try {
            if ( this.signAlgorithm!=null ) {
                operation.taskWithSigning(this.signAlgorithm, this.provider);
                return true;
            }
            for ( final String trySignAlgorithm : this.availableSignAlgorithms ) {
                try {
                    operation.taskWithSigning(trySignAlgorithm, this.provider);
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
