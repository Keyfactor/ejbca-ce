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

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Map.Entry;

/**
 * @author Lars Silven, PrimeKey Solutions AB
 * @version $Id$
 */
public class PerformanceTest {

    private final int STATISTIC_UPDATE_PERIOD_IN_SECONDS = 10;
    private final Log log;
    private final Random random;
    public PerformanceTest() {
        this.log =new Log();
        this.random = new Random();
    }
    public Log getLog() {
        return this.log;
    }
    public Random getRandom() {
        return this.random;
    }
    public interface CommandFactory {
        Command[] getCommands() throws Exception;
    }
    public interface Command {
        boolean doIt() throws Exception;

        String getJobTimeDescription();
    }
    private class JobRunner implements Runnable {
        final private Command command;
        private boolean bIsFinished;
        private int time;
        private boolean isSuccess = false;
        JobRunner( Command _command ) throws Exception {
            this.bIsFinished = false;
            this.command = _command;
        }
        boolean execute() throws Exception {
            final Thread thread = new Thread(this);
            synchronized(this) {
                thread.start();
                if ( !this.bIsFinished ) {
                    this.wait(300000);
                }
                if ( !this.bIsFinished ) {
                    thread.interrupt();
                    throw new Exception("Command not finished. See the error printout just above.");
                }
            }
            return this.isSuccess;
        }
        public void run() {
            try {
                final long startTime = new Date().getTime();
                this.isSuccess = this.command.doIt();
                this.time = (int)(new Date().getTime()-startTime);
                this.bIsFinished = true;
            } catch (Throwable t) {
                PerformanceTest.this.log.error("Command failure", t);
            } finally {
                synchronized(this) {
                    this.notifyAll();
                }
            }
        }
        public int getTimeConsumed() {
            return this.time;
        }
    }
    private class TestInstance implements Runnable {
        final private int nr;
        final private int maxWaitTime;
        final private Statistic statistic;
        final private Command commands[];
        /**
         * @param certificateProfileName 
         */
        public TestInstance(int _nr, int _waitTime, Statistic _statistic,
                            CommandFactory commandFactory) throws Exception {
            this.nr = _nr;
            this.maxWaitTime = _waitTime;
            this.statistic = _statistic;
            this.commands = commandFactory.getCommands();
            if ( this.nr > 0 ) {
                return;
            }
            final StringWriter sw = new StringWriter();
            final PrintWriter pw = new PrintWriter(sw);
            pw.println("Performance test started. The following \"Command\" classes are used for each test:");
            for (int i=0; i<this.commands.length; i++) {
                pw.println(this.commands[i].getClass().getCanonicalName());
            }
            PerformanceTest.this.log.info(sw.toString());
        }

        /* (non-Javadoc)
         * @see java.lang.Runnable#run()
         */
        public void run() {
            PerformanceTest.this.log.info("Thread nr "+ this.nr +" started.");
            while(true) {
                try {
                    final long startTime = new Date().getTime();
                    Command failingCommand = null;
                    for (int i=0; failingCommand==null && i<this.commands.length; i++) {
                        if ( this.maxWaitTime > 0 ) {
                            final int waitTime = (int)(this.maxWaitTime*PerformanceTest.this.random.nextFloat());
                            if ( waitTime > 0) {
                                synchronized(this) {
                                    wait(waitTime);
                                }
                                this.statistic.addTime("Relative time waiting between jobs",waitTime);
                            }
                        }
                        final Command command = this.commands[i];
                        final JobRunner jobRunner = new JobRunner(command);
                        if ( !jobRunner.execute() ) {
                            failingCommand = command;
                        }
                        this.statistic.addTime(command.getJobTimeDescription(), jobRunner.getTimeConsumed());
                    }
                    String sResult = "Test in thread "+this.nr+" completed ";
                    if ( failingCommand==null ) {
                        this.statistic.taskFinished();
                        sResult += "successfully";
                    } else {
                        this.statistic.taskFailed();
                        sResult += "but failed when the command '"+failingCommand.getClass().getCanonicalName()+"' was executed";
                    }
                    sResult += ". The time it took was "+(new Date().getTime()-startTime) + " ms.";
                    if ( failingCommand==null ) {
                        PerformanceTest.this.log.info(sResult);
                    } else {
                        PerformanceTest.this.log.error(sResult);
                    }
                } catch( Throwable t ) {
                    this.statistic.taskFailed();
                    PerformanceTest.this.log.error("Exeption in thread "+this.nr+".", t);
                }
            }
        	
        }
    }

    public void execute(CommandFactory commandFactory, int numberOfThreads, int waitTime, PrintStream printStream) throws Exception {

        final Statistic statistic = new Statistic(numberOfThreads, printStream);
        final Thread threads[] = new Thread[numberOfThreads];
        for(int i=0; i < numberOfThreads;i++) {
            threads[i] = new Thread(new TestInstance(i, waitTime, statistic, commandFactory));
        }
        for(int i=0; i < numberOfThreads;i++) {
            threads[i].start();
        }
        new Thread(statistic).start();
        printStream.println("Test client started, tail info and error files in this directory for output.");
        printStream.println("Statistic will be written to standard output each "+this.STATISTIC_UPDATE_PERIOD_IN_SECONDS+" second.");
        synchronized(this) {
            wait();
        }
    }
    private class Statistic implements Runnable {
        private final int nr;
        private final Map<String, Long> mTimes;
        private int nrOfSuccesses = 0;
        private int nrOfSuccessesLastTime = 0;
        private int nrOfFailures = 0;
        private long startTime;
        private final PrintStream printStream;
        Statistic(int _nr, PrintStream _printStream) {
            this.nr = _nr;
            this.mTimes = new HashMap<String, Long>();
            this.printStream = _printStream;
        }
        void taskFailed() {
            this.nrOfFailures++;
        }
        void taskFinished() {
            this.nrOfSuccesses++;
        }
        Statistic(int nr) {
            this(nr, System.out);
        }
        void addTime(String timeName, long duration) {
            final long lastTime;
            if ( this.mTimes.containsKey(timeName) ) {
                lastTime = this.mTimes.get(timeName).longValue();
            } else {
                lastTime = 0;
            }
            this.mTimes.put(timeName, new Long(lastTime+duration));
        }
        private void printLine(String description, Object value) {
            String padding = new String();
            for ( int i=description.length(); i<50; i++ ) {
                padding += ' ';
            }
            this.printStream.println(description+": "+padding+value);
        }
        private void printStatistics() {
            final long time = (int)(new Date().getTime()-this.startTime);
            final long allThreadsTime = this.nr*time;
            final Float testsPerSecond = new Float((float)this.nrOfSuccesses*1000/time);
            final Float testsPerSecondInLastPeriod = new Float((float)(this.nrOfSuccesses - this.nrOfSuccessesLastTime)/PerformanceTest.this.STATISTIC_UPDATE_PERIOD_IN_SECONDS);
            this.nrOfSuccessesLastTime = this.nrOfSuccesses;
            final float relativeWork; {
                long tmp = 0;
                Iterator<Long> i=this.mTimes.values().iterator();
                while (i.hasNext() ) {
                    tmp += i.next().longValue();
                }
                relativeWork = (float)(allThreadsTime-tmp) / allThreadsTime;
            }
            final String CSI = "\u001B[";

            this.printStream.println(CSI+"J"); // clear rest of screen on VT100 terminals.
            printLine("Total # of successfully performed tests", new Integer(this.nrOfSuccesses));
            printLine("Total # of failed tests", new Integer(this.nrOfFailures));
            printLine("# of tests completed each second", testsPerSecond);
            printLine("# of tests completed each second in last period", testsPerSecondInLastPeriod);
            final Iterator<Entry<String, Long>> i = this.mTimes.entrySet().iterator();
            while( i.hasNext() ) {
                final Entry<String, Long> entry = i.next();
                printLine(entry.getKey(), new Float((float)entry.getValue().longValue() / allThreadsTime));
            }
            printLine("Relative time spent with test client work", new Float(relativeWork));
            this.printStream.print(CSI+(6+this.mTimes.size())+"A"); // move up.
            this.printStream.flush();
        }
        public void run() {
            this.startTime = new Date().getTime();
            while(true) {
                synchronized(this) {
                    try {
                        wait(PerformanceTest.this.STATISTIC_UPDATE_PERIOD_IN_SECONDS*1000);
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
                this.errorPrinter = new PrintWriter(new FileWriter("error.log"));
                this.infoPrinter = new PrintWriter(new FileWriter("info.log"));
                this.allPrinter = new PrintWriter(new FileWriter("all.log"));
                this.resultObject = new ObjectOutputStream(new FileOutputStream("result.log", true));
                this.inUse=false;
            } catch (IOException e) {
                System.out.println("Error opening log file. "+e.getMessage());
                System.exit(-1);
                throw new Error(e);
            }
        }
        public void close() {
            this.errorPrinter.close();
            this.infoPrinter.close();
            this.allPrinter.close();
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
                        if ( this.printer!=null ) {
                            if ( this.doPrintDate ) {
                                this.printer.print(currentDate + " : ");
                            }
                            this.printer.println(this.msg);
                            if(this.t != null){
                                this.t.printStackTrace(this.printer);
                                this.printer.println();
                            }
                            this.printer.flush();
                        }
                        if ( this.objectOutput!=null ) {
                            this.objectOutput.writeObject(this.msg);
                        }
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
            new Thread(new LogThread(object, this.resultObject)).start();
        }
        public void error(String msg,Throwable t)  {
            log(msg, t, this.errorPrinter);
            log(msg, t, this.allPrinter);
        }
        public void error(String msg)  {
            error(msg, null);
        }
        public void info(String msg,Throwable t) {
            log(msg, t, this.infoPrinter);
            log(msg, t, this.allPrinter);
        }
        public void info(String msg) {
            info(msg,null);
        }
    }
}
