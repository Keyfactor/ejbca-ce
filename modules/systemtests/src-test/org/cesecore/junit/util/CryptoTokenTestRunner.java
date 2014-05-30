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
package org.cesecore.junit.util;

import java.lang.reflect.Constructor;
import java.util.List;

import org.cesecore.certificates.ca.X509CA;
import org.junit.internal.AssumptionViolatedException;
import org.junit.internal.runners.model.EachTestNotifier;
import org.junit.runner.notification.RunNotifier;
import org.junit.runner.notification.StoppedByUserException;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.Statement;

/**
 * Base class for crypto token variations of the test runner. 
 * 
 * @version $Id$
 *
 */
public abstract class CryptoTokenTestRunner extends BlockJUnit4ClassRunner {

    protected X509CA x509ca;
    protected int cryptoTokenId;
    
    public CryptoTokenTestRunner(Class<?> klass) throws InitializationError {
        super(klass);
    }
    
    /**
     * Series of instructions to perform before a test class.
     */
    protected abstract void beforeClass() throws Exception;

    /**
     * Series of instructions to perform after a test class
     */
    protected abstract void afterClass();
    
    
    @Override
    protected void validateConstructor(List<Throwable> errors) {
        validateOnlyOneConstructor(errors);
        //Validate parameters of class
        Constructor<?>[] constructors = getTestClass().getJavaClass().getConstructors();
        Class<?>[] parameters = constructors[0].getParameterTypes();
        if (parameters.length != 2) {
            errors.add(new Exception("Incorrect number of parameters in constructor"));
        }
        if (!parameters[0].equals(X509CA.class) && !parameters[1].equals(int.class)) {
            errors.add(new Exception("Constructor arguments were not X509CA,int"));
        }
    }

    /**
     * Returns a new fixture for running a test. 
     */
    @Override
    protected Object createTest() throws Exception {
        return getTestClass().getOnlyConstructor().newInstance(x509ca, cryptoTokenId);
    }

    @Override
    public void run(final RunNotifier notifier) {
        EachTestNotifier testNotifier = new EachTestNotifier(notifier, getDescription());
        try {
            beforeClass();
            Statement statement = classBlock(notifier);
            statement.evaluate();
            afterClass();
        } catch (AssumptionViolatedException e) {
            testNotifier.fireTestIgnored();
        } catch (StoppedByUserException e) {
            throw e;
        } catch (Throwable e) {
            testNotifier.addFailure(e);
        }
    }
    
    @Override
    // The name of the test class  
    protected String getName() {
        return String.format("%s [%s]", super.getName(), getSubtype());
    }

    @Override
    // The name of the test method  
    protected String testName(final FrameworkMethod method) {
        return String.format("%s [%s]", method.getName(), getSubtype());
    }
    
    public abstract String getSubtype();

}
