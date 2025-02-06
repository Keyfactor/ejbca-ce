/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.ws.client;

import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.util.PerformanceTest;

import java.util.Random;

public abstract class StressTestCommandBase extends EJBCAWSRABaseCommand implements IAdminCommand {
    final static public String USER_NAME_TAG = "<userName>";
    private static PerformanceTest PERFORMANCE_TEST = new PerformanceTest();

    enum TestType {
        BASIC,
        BASICSINGLETRANS,
        BASICSINGLETRANS_SAMEUSER,
        REVOKE,
        REVOKE_BACKDATED,
        REVOKEALOT
    }

    StressTestCommandBase(String[] args) {
        super(args);
    }

    @Override
    protected abstract void usage();

    protected abstract PerformanceTest.CommandFactory getCommandFactory(
            String caName,
            String endEntityProfileName,
            String certificateProfileName,
            TestType testType,
            int maxCertificateSN,
            String subjectDN,
            String keyAlgorithm,
            int keySize,
            String curve
    );

    @Override
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {

        try {
            if(this.args.length < 2){
                usage();
                System.exit(-1); // NOPMD, this is not a JEE app
            }
            PerformanceTest.NrOfThreadsAndNrOfTests notanot = new PerformanceTest.NrOfThreadsAndNrOfTests(this.args.length>2 ? this.args[2] : null);
            final int waitTime = this.args.length>3 ? Integer.parseInt(this.args[3]) : -1;
            final String caName = this.args[1];
            final String endEntityProfileName = this.args.length>4 ? this.args[4] : "EMPTY";
            final String certificateProfileName = this.args.length>5 ? this.args[5] : "ENDUSER";
            final TestType testType = this.args.length>6 ? TestType.valueOf(this.args[6]) : TestType.BASIC;
            if (notanot.getTests() == -1) {
                notanot.setTests(this.args.length>7 ? Integer.parseInt(this.args[7]) : -1);
            }
            final int maxCertificateSN;
            final String subjectDN = System.getProperty("subjectDN", "CN="+USER_NAME_TAG);
            {
                final String sTmp = System.getProperty("maxCertSN");
                int iTmp;
                try {
                    iTmp = sTmp!=null && sTmp.length()>0 ? Integer.parseInt(sTmp) : -1;
                } catch ( NumberFormatException e ) {
                    iTmp = -1;
                }
                maxCertificateSN = iTmp;
            }
            final String keyAlgorithm = System.getProperty("keyAlgorithm", "RSA");
            final String curve = System.getProperty("curve", "secp192r1");
            final int keySize = Integer.parseInt(System.getProperty("keySize",
                    keyAlgorithm.equals("RSA") ? "1024" : "571"));


            this.PERFORMANCE_TEST.execute(
                    getCommandFactory(
                            caName,
                            endEntityProfileName,
                            certificateProfileName,
                            testType,
                            maxCertificateSN,
                            subjectDN,
                            keyAlgorithm,
                            keySize,
                            curve
                    ),
                    notanot.getThreads(),
                    notanot.getTests(),
                    waitTime,
                    getPrintStream()
            );
            getPrintStream().println("A test key for each thread is generated. This could take some time if you have specified many threads and long keys.");
            synchronized(this) {
                wait();
            }
        } catch( InterruptedException e) {
            // do nothing since user wants to exit.
        } catch( Exception e) {
            throw new ErrorAdminCommandException(e);
        }finally{
            this.PERFORMANCE_TEST.getLog().close();
        }
    }

    public static long nextLong(boolean forCvc) {
        return PERFORMANCE_TEST.nextLong(forCvc);
    }

    public static long generateUniqueUsernameNumber() {
        return PERFORMANCE_TEST.generateUniqueUsernameNumber();
    }

    public static PerformanceTest.Log getLog() {
        return PERFORMANCE_TEST.getLog();
    }

    public static Random getRandom() {
        return PERFORMANCE_TEST.getRandom();
    }
}
