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
package org.ejbca.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Map.Entry;

/**
 * @author Lars Silven, PrimeKey Solutions AB
 * @version $Id: PerformanceTest.java,v 1.2 2008-03-08 22:41:04 primelars Exp $
 */
public class PerformanceTest {

    private final int STATISTIC_UPDATE_PERIOD_IN_SECONDS = 10;
    private final Log log;
    private final Random random;
    public PerformanceTest() {
        log =new Log();
        random = new Random();
    }
    public Log getLog() {
        return log;
    }
    public Random getRandom() {
        return random;
    }
    public interface CommandFactory {
        Command[] getCommands() throws Exception;
    }
    public interface Command {
        void doIt() throws Exception;

        String getJobTimeDescription();
    }
    private class JobRunner implements Runnable {
        final private Command command;
        private boolean bIsFinished;
        private int time;
        JobRunner( Command _command ) throws Exception {
            bIsFinished = false;
            this.command = _command;
        }
        void execute() throws Exception {
            final Thread thread = new Thread(this);
            synchronized(this) {
                thread.start();
                if ( !bIsFinished )
                    this.wait(120000);
                if ( !bIsFinished ) {
                    thread.interrupt();
                    throw new Exception("Command not finished. See the error printout just above.");
                }
            }
        }
        public void run() {
            try {
                final long startTime = new Date().getTime();
                command.doIt();
                time = (int)(new Date().getTime()-startTime);
                bIsFinished = true;
            } catch (Throwable t) {
                log.error("Command failure", t);
            } finally {
                synchronized(this) {
                    this.notifyAll();
                }
            }
        }
        public int getTimeConsumed() {
            return time;
        }
    }
    private class TestInstance implements Runnable {
        final private int nr;
        final private int maxWaitTime;
        final private Statistic statistic;
        final private Command commands[];
        /**
         * @param certificateProfileName 
         * @throws NoSuchAlgorithmException 
         * @throws IOException 
         * @throws FileNotFoundException 
         * 
         */
        public TestInstance(int _nr, Log _log, int _waitTime, Statistic _statistic,
                            CommandFactory commandFactory) throws Exception {
            this.nr = _nr;
            this.maxWaitTime = _waitTime;
            this.statistic = _statistic;
            this.commands = commandFactory.getCommands();
        }

        /* (non-Javadoc)
         * @see java.lang.Runnable#run()
         */
        public void run() {
            log.info("Thread nr "+ nr +" started.");
            while(true) {
                try {
                    for (int i=0; i<commands.length; i++) {
                        if ( this.maxWaitTime > 0 ) {
                            final int waitTime = (int)(this.maxWaitTime*random.nextFloat());
                            if ( waitTime > 0) {
                                synchronized(this) {
                                    wait(waitTime);
                                }
                                this.statistic.addTime("Relative time waiting between jobs",waitTime);
                            }
                        }
                        final JobRunner jobRunner = new JobRunner(commands[i]);
                        jobRunner.execute();
                        this.statistic.addTime(commands[i].getJobTimeDescription(), jobRunner.getTimeConsumed());
                    }
                    this.statistic.taskFinished();
                } catch( Throwable t ) {
                    log.error("Exeption in thread "+nr+".", t);
                }
            }
        }
    }

    public void execute(CommandFactory commandFactory, int numberOfThreads, int waitTime, PrintStream printStream) throws Exception {

        final Statistic statistic = new Statistic(numberOfThreads, printStream);
        final Thread threads[] = new Thread[numberOfThreads];
        for(int i=0; i < numberOfThreads;i++)
            threads[i] = new Thread(new TestInstance(i, log, waitTime, statistic, commandFactory));
        for(int i=0; i < numberOfThreads;i++)
            threads[i].start();
        new Thread(statistic).start();
        printStream.println("Test client started, tail info and error files in this directory for output.");
        printStream.println("Statistic will be written to standard output each "+STATISTIC_UPDATE_PERIOD_IN_SECONDS+" second.");
        synchronized(this) {
            wait();
        }
    }
    private class Statistic implements Runnable {
        private final int nr;
        private final Map<String, Long> mTimes;
        private int nrOfTests = 0;
        private long startTime;
        private final PrintStream printStream;
        Statistic(int _nr, PrintStream _printStream) {
            this.nr = _nr;
            mTimes = new HashMap<String, Long>();
            printStream = _printStream;
        }
        void taskFinished() {
            nrOfTests++;
        }
        Statistic(int nr) {
            this(nr, System.out);
        }
        void addTime(String timeName, long duration) {
            final long lastTime;
            if ( mTimes.containsKey(timeName) )
                lastTime = mTimes.get(timeName);
            else
                lastTime = 0;
            mTimes.put(timeName, new Long(lastTime+duration));
        }
        private void printLine(String description, Object value) {
            String padding = new String();
            for ( int i=description.length(); i<50; i++ )
                padding += ' ';
            printStream.println(description+": "+padding+value);
        }
        private void printStatistics() {
            final long time = (int)(new Date().getTime()-this.startTime);
            final long allThreadsTime = this.nr*time;
            final float signingsPerSecond = (float)nrOfTests*1000/time;
            final float relativeWork; {
                long tmp = 0;
                Iterator<Long> i=mTimes.values().iterator();
                while (i.hasNext() )
                    tmp += i.next().longValue();
                relativeWork = (float)(allThreadsTime-tmp) / allThreadsTime;
            }
            final String CSI = "\u001B[";

            printStream.println(CSI+"J"); // clear rest of screen on VT100 terminals.
            printLine("Total # of successfully performed tests", nrOfTests);
            printLine("# of tests completed each second", signingsPerSecond);
            final Iterator<Entry<String, Long>> i = mTimes.entrySet().iterator();
            while( i.hasNext() ) {
                final Entry<String, Long> entry = i.next();
                printLine(entry.getKey(), (float)entry.getValue().longValue() / allThreadsTime);
            }
            printLine("Relative time spent with test client work", relativeWork);
            printStream.print(CSI+(4+mTimes.size())+"A"); // move up 7 rows.
            printStream.flush();
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
    public class Log {
        private final PrintWriter errorPrinter;
        private final PrintWriter infoPrinter;
        private final PrintWriter allPrinter;
        private final ObjectOutput resultObject;
        private boolean inUse;
        Log() {
            try {
                errorPrinter = new PrintWriter(new FileWriter("error.log"));
                infoPrinter = new PrintWriter(new FileWriter("info.log"));
                allPrinter = new PrintWriter(new FileWriter("all.log"));
                resultObject = new ObjectOutputStream(new FileOutputStream("result.log"));
                inUse=false;
            } catch (IOException e) {
                System.out.println("Error opening log file. "+e.getMessage());
                System.exit(-1);
                throw new Error(e);
            }
        }
        public void close() {
            errorPrinter.close();
            infoPrinter.close();
            allPrinter.close();
        }
        private class LogThread implements Runnable {
            final Object msg;
            final Throwable t;
            final PrintWriter printer;
            final ObjectOutput objectOutput;
            final boolean doPrintDate;
            private LogThread(Object _msg,Throwable _t, PrintWriter _printer, ObjectOutput _objectOutput, boolean _doPrintDate) {
                this.msg=_msg;
                this.t=_t;
                this.printer=_printer;
                this.doPrintDate = _doPrintDate;
                this.objectOutput = _objectOutput;
            }
            LogThread(String msg, Throwable t, PrintWriter printer, boolean doPrintDate) {
                this(msg, t, printer, null, doPrintDate);
            }
            LogThread(Object msg, ObjectOutput objectOutput) {
                this(msg, null, null, objectOutput, false);
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
                        if ( printer!=null ) {
                            if ( doPrintDate )
                                printer.print(currentDate + " : ");
                            printer.println(msg);
                            if(t != null){
                                t.printStackTrace(printer);
                                printer.println();
                            }
                            printer.flush();
                        }
                        if ( objectOutput!=null )
                            objectOutput.writeObject(msg);
                    } catch( IOException e ) {
                        error("Logging fault", e);
                    } finally {
                        Log.this.inUse = false;
                        Log.this.notifyAll();
                    }
                }
            }
        }
        private void log(String msg,Throwable t, PrintWriter printer)  {
            new Thread(new LogThread(msg, t, printer, true)).start();
        }
        public void result(Object object ) {
            new Thread(new LogThread(object, resultObject)).start();
        }
        public void error(String msg,Throwable t)  {
            log(msg, t, errorPrinter);
            log(msg, t, allPrinter);
        }
        public void error(String msg)  {
            error(msg, null);
        }
        public void info(String msg,Throwable t) {
            log(msg, t, infoPrinter);
            log(msg, t, allPrinter);
        }
        public void info(String msg) {
            info(msg,null);
        }
    }
}
