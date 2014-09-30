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
package org.ejbca.ui.cli;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;

/**
 * Used to test the EJBCA health check servlet.
 * 
 * @version $Id$
 *
 */
class HealthCheckTest extends ClientToolBox {
    static private class StressTest {
        final PerformanceTest performanceTest;
        StressTest( final String httpPath,
                    final int numberOfThreads,
                    final int waitTime) throws Exception {
            performanceTest = new PerformanceTest();
            performanceTest.execute(new MyCommandFactory(httpPath), numberOfThreads, waitTime, System.out);
        }
        private class GetStatus implements Command {
            
            final private URL url;
            GetStatus(URL _url) {
                this.url = _url;
            }
            public boolean doIt() throws Exception {
                final HttpURLConnection con = (HttpURLConnection)url.openConnection();
                if ( con.getResponseCode()!=HttpURLConnection.HTTP_OK ) {
                    performanceTest.getLog().error("Wrong response code: "+con.getResponseCode());
                    return false;
                }
                if ( !con.getResponseMessage().equals("OK") ) {
                    performanceTest.getLog().error("Wrong response message: "+con.getResponseMessage());
                    return false;
                }
                final Object content = con.getContent();
                if ( ! (content instanceof InputStream) ) {
                    performanceTest.getLog().error("Content is not an input stream.");
                    return false;
                }
                final InputStream is = (InputStream) content;
                try {
                    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    while (true) {
                        int nextByte = is.read();
                        if (nextByte < 0) {
                            break;
                        }
                        baos.write(nextByte);
                    }
                    if (!baos.toString().equals("ALLOK")) {
                        performanceTest.getLog().error("Wrong content: " + baos);
                        return false;
                    }
                    performanceTest.getLog().info("Health OK! ");
                    return true;
                } finally {
                    is.close();
                }
            }
            public String getJobTimeDescription() {
                return "Get health status";
            }
        }
        private class MyCommandFactory implements CommandFactory {
            private final URL url;
            MyCommandFactory(String httpPath) throws MalformedURLException {
                super();
                url = new URL(httpPath);
            }
            public Command[] getCommands() throws Exception {
                return new Command[]{new GetStatus(url)};
            }
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
	protected void execute(String[] args) {
        final String httpPath;
        final int numberOfThreads;
        final int waitTime;
        if ( args.length < 2 ) {
            System.out.println(args[0]+" <http URL> [<number of threads>] [<wait time (ms) between each thread is started>]");
            System.out.println("Example: ");
            return;
        }
        httpPath = args[1];
        numberOfThreads = args.length>2 ? Integer.parseInt(args[2].trim()):1;
        waitTime = args.length>3 ? Integer.parseInt(args[3].trim()):0;
        try {
            new StressTest(httpPath, numberOfThreads, waitTime);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    protected String getName() {
        return "healthCheckTest";
    }

}
