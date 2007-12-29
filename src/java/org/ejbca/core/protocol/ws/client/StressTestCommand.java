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
package org.ejbca.core.protocol.ws.client;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.util.CertTools;

/**
 * @author Lars Silvén, PrimeKey Solutions AB
 * @version $Id: StressTestCommand.java,v 1.5 2007-12-29 15:24:33 primelars Exp $
 */
public class StressTestCommand extends EJBCAWSRABaseCommand implements IAdminCommand {

    private final int STATISTIC_UPDATE_PERIOD_IN_SECONDS = 10;
    
    class TestInstance implements Runnable {
        final private Log log;
        final private int nr;
        final private String caName;
        final private int maxWaitTime;
        final private Statistic statistic;
        final private KeyPair keys;
        final private Random random;
        final private EjbcaWS ejbcaWS;
        /**
         * @throws NoSuchAlgorithmException 
         * @throws IOException 
         * @throws FileNotFoundException 
         * 
         */
        public TestInstance(int _nr, Log _log, String _caName, int _waitTime, Statistic _statistic, Random _random) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
            this.log = _log;
            this.nr = _nr;
            this.caName = _caName;
            this.maxWaitTime = _waitTime;
            this.statistic = _statistic;
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            this.keys = kpg.generateKeyPair();
            this.random = _random;
            this.ejbcaWS = getEjbcaRAWSFNewReference();
        }

        /* (non-Javadoc)
         * @see java.lang.Runnable#run()
         */
        public void run() {
            log.info("Thread nr "+ nr +" started.");
            while(true) {
                try {
                    final String userName = "WSTESTUSER"+random.nextInt();
                    final String passWord = "foo123";
                    addUser(userName, passWord);
                    final int waitTime;
                    if ( this.maxWaitTime > 0 ) {
                        waitTime = (int)(this.maxWaitTime*random.nextFloat());
                        synchronized(this) {
                            wait(waitTime);
                        }
                        this.statistic.addWaitTime(waitTime);
                    } else
                        waitTime = 0;
                    final X509Certificate cert = getCertificate(userName, passWord, this.keys);
                    final String commonName = CertTools.getPartFromDN(cert.getSubjectDN().getName(), "CN");
                    if ( commonName.equals(userName) )
                        log.info("Cert created. Subject DN: \""+cert.getSubjectDN()+"\". Client waited "+waitTime+"ms before fetching the cert. CN="+commonName);
                    else
                        log.error("Cert not created for right user. Username: \""+userName+"\" Subject DN: \""+cert.getSubjectDN()+"\".");
                } catch( Throwable t ) {
                    log.error("Exeption in thread "+nr+".", t);
                }
            }
        }
        private void addUser(String userName, String passWord) throws Exception {
            final UserDataVOWS user1 = new UserDataVOWS();
            user1.setUsername(userName);
            user1.setPassword(passWord);
            user1.setClearPwd(true);
            user1.setSubjectDN("CN="+userName);
            user1.setCaName(caName);
            user1.setEmail(null);
            user1.setSubjectAltName(null);
            user1.setStatus(UserDataConstants.STATUS_NEW);
            user1.setTokenType(org.ejbca.core.protocol.ws.objects.UserDataVOWS.TOKEN_TYPE_USERGENERATED);
            user1.setEndEntityProfileName("EMPTY");
            user1.setCertificateProfileName("ENDUSER");
            final long startTime = new Date().getTime();
            this.ejbcaWS.editUser(user1);
            this.statistic.addRegisterTime(new Date().getTime()-startTime);
        }
        @SuppressWarnings("unchecked")
        private X509Certificate getCertificate(String userName, String passWord, KeyPair keys) throws Exception{
            final PKCS10CertificationRequest  pkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOUSED"), keys.getPublic(), null, keys.getPrivate());

            final long startTime = new Date().getTime();
            final CertificateResponse certenv = this.ejbcaWS.pkcs10Request(userName, passWord, new String(Base64.encode(pkcs10.getEncoded())),null,CertificateHelper.RESPONSETYPE_CERTIFICATE);
            this.statistic.addSignTime(new Date().getTime()-startTime);
            final Iterator<X509Certificate> i = (Iterator<X509Certificate>)CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(Base64.decode(certenv.getData()))).iterator();
            X509Certificate cert = null;
            while ( i.hasNext() )
                cert = i.next();
            return cert;
        }
    }
    /**
     * @param args
     */
    public StressTestCommand(String[] _args) {
        super(_args);
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.protocol.ws.client.EJBCAWSRABaseCommand#usage()
     */
    @Override
    protected void usage() {
        getPrintStream().println("Command used to perform a \"stress\" test of EJBCA.");
        getPrintStream().println("The command will start up a number of threads.");
        getPrintStream().println("Each thread will continuously add new users to EJBCA. After adding a new user the thread will fetch a certificate for it.");
        getPrintStream().println();
        getPrintStream().println("Usage : stress <caname> <nr of threads> <max wait time in ms to fetch cert after adding user>");
        getPrintStream().println();
        getPrintStream().println("Here is an example of how the test could be started:");
        getPrintStream().println("./ejbcawsracli.sh stress AdminCA1 20 5000");
        getPrintStream().println("20 threads is started. After adding a user the thread waits between 0-500 ms before requesting a certificate for it. The certificates will all be signed by the CA AdminCA1.");
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.IAdminCommand#execute()
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {

        Log log = null;
        try {
            log = new Log();
            if(args.length <  2){
                usage();
                System.exit(-1);
            }
            final int numberOfThreads = args.length>2 ? Integer.parseInt(args[2]) : 1;
            final int waitTime = args.length>3 ? Integer.parseInt(args[3]) : -1;
            final String caName = args[1];
            final Statistic statistic = new Statistic(numberOfThreads);
            final Thread threads[] = new Thread[numberOfThreads];
            final Random random = new Random();
            for(int i=0; i < numberOfThreads;i++)
                threads[i] = new Thread(new TestInstance(i,log, caName, waitTime, statistic, random));
            for(int i=0; i < numberOfThreads;i++)
                threads[i].start();
            new Thread(statistic).start();
            System.out.println("Test client started, tail info and error files in this directory for output.");
            System.out.println("Statistic will be written to standard output each "+STATISTIC_UPDATE_PERIOD_IN_SECONDS+" second.");
            synchronized(this) {
                wait();
            }
        } catch( InterruptedException e) {
            throw new ErrorAdminCommandException(e);
        } catch( NoSuchAlgorithmException e) {
            throw new ErrorAdminCommandException(e);
        } catch (FileNotFoundException e) {
            throw new ErrorAdminCommandException(e);
        } catch (IOException e) {
            throw new ErrorAdminCommandException(e);
        }finally{
            if ( log!=null )
                log.close();
        }
    }
    private class Statistic implements Runnable {
        private final int nr;
        private int registerTime = 0;
        private int signTime = 0;
        private int waitTime = 0;
        private int nrOfSignings = 0;
        private long startTime;
        Statistic(int _nr) {
            this.nr = _nr;
        }
        public void addWaitTime(int additionalWaitTime) {
            waitTime += additionalWaitTime;
        }
        void addRegisterTime(long time) {
            registerTime += time;
        }
        void addSignTime(long time) {
            signTime += time;
            nrOfSignings++;
        }
        private void printStatistics() {
            final long time = new Date().getTime()-this.startTime;
            final long allThreadsTime = this.nr*time;
            final float signingsPerSecond = (float)nrOfSignings*1000/time;
            final float relativeWork = (float)(allThreadsTime-this.waitTime-this.signTime-registerTime) / allThreadsTime;
            final float relativeWait = (float)this.waitTime / allThreadsTime;
            final float relativeSign = (float)this.signTime / allThreadsTime;
            final float relativeRegister = (float)registerTime / allThreadsTime;
            final String CSI = "\u001B[";
            StressTestCommand.this.getPrintStream().println(CSI+"J"); // clear rest of screen on VT100 terminals.
            StressTestCommand.this.getPrintStream().println("Total # of signed certificates:                   "+nrOfSignings);
            StressTestCommand.this.getPrintStream().println("# of certs signed each second:                    "+signingsPerSecond);
            StressTestCommand.this.getPrintStream().println("Relative time spent registring new users:         "+relativeRegister);
            StressTestCommand.this.getPrintStream().println("Relative time spent signing certificates:         "+relativeSign);
            StressTestCommand.this.getPrintStream().println("Relative time spent with test client work:        "+relativeWork);
            StressTestCommand.this.getPrintStream().println("Relative time spent waiting to fetch certificate: "+relativeWait);
            StressTestCommand.this.getPrintStream().print(CSI+"7A"); // move up 7 rows.
            StressTestCommand.this.getPrintStream().flush();
        }
        public void run() {
            startTime = new Date().getTime();
            while(true) {
                synchronized(this) {
                    try {
                        wait(STATISTIC_UPDATE_PERIOD_IN_SECONDS*1000);
                    } catch (InterruptedException e) {
                        // do nothing
                    }
                }
                printStatistics();
            }
        }
    }
    private class Log {
        private final PrintWriter errorPrinter;
        private final PrintWriter infoPrinter;
        private final PrintWriter allPrinter;
        private boolean inUse;
        Log() {
            try {
                errorPrinter = new PrintWriter(new FileWriter("error.log"));
                infoPrinter = new PrintWriter(new FileWriter("info.log"));
                allPrinter = new PrintWriter(new FileWriter("all.log"));
                inUse=false;
            } catch (IOException e) {
                System.out.println("Error opening log file. "+e.getMessage());
                System.exit(-1);
                throw new Error(e);
            }
        }
        void close() {
            errorPrinter.close();
            infoPrinter.close();
            allPrinter.close();
        }
        private class LogThread implements Runnable {
            final String msg;
            final Throwable t;
            final PrintWriter printer;
            LogThread(String _msg,Throwable _t, PrintWriter _printer) {
                this.msg=_msg;
                this.t=_t;
                this.printer=_printer;
            }
            @SuppressWarnings("synthetic-access")
            public void run() {
                final Date currentDate = new Date();
                synchronized(Log.this) {
                    while ( Log.this.inUse ) {
                        try {
                            Log.this.wait();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                            System.exit(-2);
                            throw new Error(e);
                        }
                    }
                    try {
                        Log.this.inUse = true;
                        printer.println(currentDate + " : " + msg);
                        if(t != null){
                            t.printStackTrace(printer);
                            printer.println();
                        }
                        printer.flush();
                    } finally {
                        Log.this.inUse = false;
                        Log.this.notifyAll();
                    }
                }
            }
        }
        private void log(String msg,Throwable t, PrintWriter printer)  {
            new Thread(new LogThread(msg, t, printer)).start();
        }
        void error(String msg,Throwable t)  {
            log(msg, t, errorPrinter);
            log(msg, t, allPrinter);
        }
        void error(String msg)  {
            error(msg, null);
        }
        void info(String msg,Throwable t) {
            log(msg, t, infoPrinter);
            log(msg, t, allPrinter);
        }
        void info(String msg) {
            info(msg,null);
        }
    }
}
