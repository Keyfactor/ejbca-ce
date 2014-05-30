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

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.internal.AssumptionViolatedException;
import org.junit.internal.runners.model.EachTestNotifier;
import org.junit.runner.Runner;
import org.junit.runner.notification.RunNotifier;
import org.junit.runner.notification.StoppedByUserException;
import org.junit.runners.Suite;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.Statement;

/**
 * This test runner will make sure that any system test marked to use it will run twice: once with a soft crypto token and once with a PKCS11-token if available. 
 * 
 * @version $Id$
 *
 */
public class VariableCryptoTokenTestRunner extends Suite {

    private static final String UTIMACO_PKCS11_LINUX_LIB = "/etc/utimaco/libcs2_pkcs11.so";
    private static final String UTIMACO_PKCS11_WINDOWS_LIB = "C:/Program Files/Utimaco/SafeGuard CryptoServer/Lib/cs2_pkcs11.dll";
    private static final String LUNASA_PKCS11_LINUX_LIB = "/usr/lunasa/lib/libCryptoki2_64.so";
    private static final String LUNASA_PKCS11_LINUX32_LIB = "/usr/lunasa/lib/libCryptoki2.so";
    private static final String PROTECTSERVER_PKCS11_LINUX_LIB = "/opt/PTK/lib/libcryptoki.so"; // this symlink is set by safeNet-install.sh->"5 Set the default cryptoki and/or hsm link". Use it instead of symlinking manually.
    private static final String PROTECTSERVER_PKCS11_LINUX64_LIB = "/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_LINUX32_LIB = "/opt/ETcpsdk/lib/linux-i386/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_WINDOWS_LIB = "C:/Program Files/SafeNet/ProtectToolkit C SDK/bin/sw/cryptoki.dll";
    
    public VariableCryptoTokenTestRunner(Class<?> klass) throws InitializationError {
        super(klass, getRunners(klass));
    }

    /**
     * 
     * @return a list of test runners. By default will only return a runner that returns soft tokens, but will include a runner for PKCS#11 tokens as well, if available. 
     * @throws InitializationError 
     */
    private static List<Runner> getRunners(Class<?> klass) throws InitializationError {
        List<Runner> runners = new ArrayList<Runner>();
        if (getHSMLibrary() != null) {
            runners.add(new PKCS11TestRunner(klass));
        }
        runners.add(new PKCS12TestRunner(klass));
        return runners;
    }

    @Override
    public void run(final RunNotifier notifier) {
        EachTestNotifier testNotifier = new EachTestNotifier(notifier, getDescription());
        try {
            Statement statement = classBlock(notifier);
            statement.evaluate();
        } catch (AssumptionViolatedException e) {
            testNotifier.fireTestIgnored();
        } catch (StoppedByUserException e) {
            throw e;
        } catch (Throwable e) {
            testNotifier.addFailure(e);
        }
    }

    /*
     * Special version of the classBlock method that avoids @BeforeClass and @AfterClass annotations and class rules on tests that are treated as suites.
     */
    @Override
    protected Statement classBlock(final RunNotifier notifier) {
        Statement statement = childrenInvoker(notifier);
        return statement;
    }
    
    private static String getHSMLibrary() {
        final File utimacoCSLinux = new File(UTIMACO_PKCS11_LINUX_LIB);
        final File utimacoCSWindows = new File(UTIMACO_PKCS11_WINDOWS_LIB);
        final File lunaSALinux64 = new File(LUNASA_PKCS11_LINUX_LIB);
        final File lunaSALinux32 = new File(LUNASA_PKCS11_LINUX32_LIB);
        final File protectServerLinux = new File(PROTECTSERVER_PKCS11_LINUX_LIB);
        final File protectServerLinux64 = new File(PROTECTSERVER_PKCS11_LINUX64_LIB);
        final File protectServerLinux32 = new File(PROTECTSERVER_PKCS11_LINUX32_LIB);
        final File protectServerWindows = new File(PROTECTSERVER_PKCS11_WINDOWS_LIB);
        String ret = null;
        if (utimacoCSLinux.exists()) {
            ret = utimacoCSLinux.getAbsolutePath();
        } else if (utimacoCSWindows.exists()) {
            ret = utimacoCSWindows.getAbsolutePath();
        } else if (lunaSALinux64.exists()) {
            ret = lunaSALinux64.getAbsolutePath();
        } else if (lunaSALinux32.exists()) {
            ret = lunaSALinux32.getAbsolutePath();
        } else if (protectServerLinux64.exists()) {
            ret = protectServerLinux64.getAbsolutePath();
        } else if (protectServerLinux32.exists()) {
            ret = protectServerLinux32.getAbsolutePath();
        } else if (protectServerLinux.exists()) {
            ret = protectServerLinux.getAbsolutePath();
        } else if (protectServerWindows.exists()) {
            ret = protectServerWindows.getAbsolutePath();
        }
        return ret;
    }

}
