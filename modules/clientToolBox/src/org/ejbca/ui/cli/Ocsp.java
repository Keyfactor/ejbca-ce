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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.ejbca.core.protocol.ocsp.OCSPUnidClient;
import org.ejbca.core.protocol.ocsp.extension.unid.OCSPUnidResponse;
import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;
import org.ejbca.util.PerformanceTest.NrOfThreadsAndNrOfTests;

/**
 * Used to stress test the OCSP interface
 *
 * @version $Id$
 */
public class Ocsp extends ClientToolBox {
    private class StressTest {
        final PerformanceTest performanceTest;
        final String ocspurl;
        final X509Certificate cacert;
        final SerialNrs serialNrs;
        final String keyStoreFileName;
        final String keyStorePassword;
        final boolean useGet;
        final private boolean getFnr;

        private class MyCommandFactory implements CommandFactory {
            MyCommandFactory() {
                super();
            }

            public Command[] getCommands() throws Exception {
                return new Command[] { new Lookup() };
            }
        }

        private class SerialNrs {
            final private List<BigInteger> vSerialNrs;

            SerialNrs(String fileName) throws FileNotFoundException, IOException, ClassNotFoundException {
                List<BigInteger> vSerialNrsTmp;
                // Try to parse it as pure text-file with one dec-encoded certificate serialnumber on each line, like the one you would get with
                // echo "select serialNumber from CertificateData where issuerDN like 'CN=ManagementCA%';" | mysql -u ejbca -p ejbca | grep -v serialNumber > ../sns.txt
                try {
                    vSerialNrsTmp = new ArrayList<BigInteger>();
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new DataInputStream(new FileInputStream(fileName))));
                    String nextLine;
                    while ((nextLine = bufferedReader.readLine()) != null) {
                        nextLine = nextLine.trim();
                        if (nextLine.length() < 1 || nextLine.startsWith("#") || nextLine.startsWith(";")) {
                            continue;
                        }
                        if (nextLine.startsWith("0x")) {
                            vSerialNrsTmp.add(new BigInteger(nextLine.substring(2), 16));
                        } else {
                            vSerialNrsTmp.add(new BigInteger(nextLine));
                        }
                    }
                    bufferedReader.close();
                } catch (Exception e1) {
                    // Fall back to the format used by EJBCA WS RA CLI stress test
                    System.out.println("Parsing as textfile failed (" + e1.getMessage() + "). Trying to use it as a file with Java Objects.");
                    vSerialNrsTmp = new ArrayList<BigInteger>();
                    InputStream is = new BufferedInputStream(new FileInputStream(fileName));
                    is.mark(1);
                    try {
                        ObjectInput oi = null;
                        while (true) {
                            for (int i = 100; oi == null && i > 0; i--) {
                                is.reset();
                                try {
                                    is.mark(i);
                                    oi = new ObjectInputStream(is);
                                } catch (StreamCorruptedException e) {
                                    is.reset();
                                    is.read();
                                }
                            }
                            if (oi == null) {
                                break;
                            }
                            try {
                                is.mark(100);
                                vSerialNrsTmp.add((BigInteger) oi.readObject());
                            } catch (StreamCorruptedException e) {
                                oi = null;
                            }
                        }
                    } catch (EOFException e) {/* do nothing*/
                    }
                }
                this.vSerialNrs = vSerialNrsTmp;
                System.out.println("Number of certificates in list: " + this.vSerialNrs.size());
            }

            BigInteger getRandom() {
                return this.vSerialNrs.get(StressTest.this.performanceTest.getRandom().nextInt(this.vSerialNrs.size()));
            }
        }

        private class Lookup implements Command {
            private final OCSPUnidClient client;

            Lookup() throws Exception {
                this.client = OCSPUnidClient.getOCSPUnidClient(StressTest.this.keyStoreFileName, StressTest.this.keyStorePassword,
                        StressTest.this.ocspurl, StressTest.this.keyStoreFileName != null, StressTest.this.getFnr);
            }

            public boolean doIt() throws Exception {
                final BigInteger currentSerialNumber = StressTest.this.serialNrs.getRandom();
                final OCSPUnidResponse response = this.client.lookup(currentSerialNumber, StressTest.this.cacert, StressTest.this.useGet);
                if (response.getErrorCode() != OCSPUnidResponse.ERROR_NO_ERROR) {
                    StressTest.this.performanceTest.getLog().error(
                            "Error querying OCSP server for " + currentSerialNumber + " . Error code is: " + response.getErrorCode());
                    return false;
                }
                if (response.getHttpReturnCode() != 200) {
                    StressTest.this.performanceTest.getLog().error("Http return code is: " + response.getHttpReturnCode());
                    return false;
                }
                StressTest.this.performanceTest.getLog().info("OCSP return value is: " + response.getStatus());
                return true;
            }

            public String getJobTimeDescription() {
                return "OCSP lookup";
            }
        }

        StressTest(String args[]) throws Exception {
            if (args.length < 7) {
                System.out
                        .println("Usage: OCSP stress <OCSP URL> <Certificate serial number file> <ca cert file> <number of threads> <wait time between requests> [<POST | GET | FNR | FNRGET | FNRPOST>] [<request signing keystore file>] [<request signing password>]");
                System.out
                        .println("Certificate serial number file is creates using the WS stress command: ./ejbcawsracli.sh stress... or could also be a text file with one serial number on each row. Start with '0x' if hex.");
                System.out.println("If the directory \"./" + OCSPUnidClient.requestDirectory
                        + "\" exists then a file for each request will be stored in this directory.");
                System.out.println();
                System.out.println("If you want to access with https and client authentication you must set the environment variable 'JAVA_OPT'.");
                System.out.println("You should set each java system properties needed with a '-D' java parameter in the JAVA_OPT string.");
                System.out
                        .println("The name of all these system properties starts with javax.net.ssl and are described in http://java.sun.com/javase/6/docs/technotes/guides/security/jsse/JSSERefGuide.html .");
                System.out.println("https is mandatory for the FNR option. An example:");
                System.out
                        .println("JAVA_OPT=\"-Djavax.net.ssl.keyStore=My-Lookup.p12 -Djavax.net.ssl.keyStorePassword=foo123 -Djavax.net.ssl.keyStoreType=pkcs12 -Djavax.net.ssl.trustStore=root.jks\" ${EJBCA_HOME}/dist/clientToolBox/ejbcaClientToolBox.sh ocsp stress https://ocsp.mysite.nu certs.txt cacert.pem 40 100 fnr");
                System.exit(1); // NOPMD, it's not a JEE app
            }
            this.ocspurl = args[2];
            this.serialNrs = new SerialNrs(args[3]);
            this.cacert = getCertFromPemFile(args[4]);
            final NrOfThreadsAndNrOfTests notanot = new NrOfThreadsAndNrOfTests(args.length>5 ? args[5] : null);
            final int waitTime = Integer.parseInt(args[6]);
            if (args.length > 7) {
                final String type = args[7].toUpperCase();
                this.useGet = type.indexOf("GET") > -1;
                this.getFnr = type.indexOf("FNR") > -1;
            } else {
                this.useGet = false;
                this.getFnr = false;
            }
            if (args.length > 8) {
                this.keyStoreFileName = args[8];
            } else {
                this.keyStoreFileName = null;
            }
            if (args.length > 9) {
                this.keyStorePassword = args[9];
            } else {
                this.keyStorePassword = null;
            }
            this.performanceTest = new PerformanceTest();
            this.performanceTest.execute(new MyCommandFactory(), notanot.threads, notanot.tests, waitTime, System.out);
        }
    }

    static X509Certificate getCertFromPemFile(String fileName) throws IOException, CertificateException {
        byte[] bytes = FileTools.getBytesFromPEM(FileTools.readFiletoBuffer(fileName), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
        return CertTools.getCertfromByteArray(bytes, X509Certificate.class);
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
    protected void execute(String[] args) {
        try {
            CryptoProviderTools.installBCProvider();

            final String ksfilename;
            final String kspwd;
            final String ocspUrlFromCLI;
            final String certfilename;
            final String cacertfilename;
            boolean useGet = false;
            boolean signRequest = false;
            if (args.length > 1 && args[1].equals("stress")) {
                new StressTest(args);
                return;
            } else if (args.length >= 6) {
                ksfilename = args[1];
                kspwd = args[2];
                ocspUrlFromCLI = args[3].equals("null") ? null : args[3];
                certfilename = args[4];
                cacertfilename = args[5];
                signRequest = true;
                if (args.length == 7) {
                    useGet = "GET".equalsIgnoreCase(args[6]);
                }
            } else if (args.length >= 4) {
                ksfilename = null;
                kspwd = null;
                ocspUrlFromCLI = args[1].equals("null") ? null : args[1];
                certfilename = args[2];
                cacertfilename = args[3];
                if (args.length == 5) {
                    useGet = "GET".equalsIgnoreCase(args[4]);
                }
            } else {
                System.out
                        .println("Usage 1: OCSP <KeyStoreFilename> <KeyStorePassword> <OCSPUrl | null> <CertificateFileName | HexEncodedCertificateSerialNumber> <CA-CertificateFileName>  [<POST | GET>]");
                System.out
                        .println("Usage 2: OCSP <OCSPUrl | null> <CertificateFileName | HexEncodedCertificateSerialNumber> <CA-CertificateFileName> [<POST | GET>]");
                System.out.println("Usage 3: OCSP stress ...");
                System.out.println("Keystore should be a PKCS12. GET requests will not use a nonce.");
                System.out
                        .println("OCSPUrl is like: http://127.0.0.1:8080/ejbca/publicweb/status/ocsp or https://127.0.0.1:8443/ejbca/publicweb/status/ocsp");
                System.out.println("OCSP response status is: GOOD=" + OCSPUnidResponse.OCSP_GOOD + ", REVOKED=" + OCSPUnidResponse.OCSP_REVOKED
                        + ", UNKNOWN=" + OCSPUnidResponse.OCSP_UNKNOWN);
                System.out.println("OcspUrl can be set to 'null', in that case the program looks for an AIA extension containing the OCSP URI.");
                System.out.println("Just the stress argument gives further info about the stress test.");
                return;
            }
            OCSPUnidResponse response = null;
            BigInteger serial = null;
            final Matcher matcher = Pattern.compile("[0-9a-fA-F]+").matcher(certfilename);
            if (matcher.matches()) {
                // It is a certificate serial number instead if a certificate filename
                try {
                    serial = new BigInteger(certfilename, 16);
                    if (ocspUrlFromCLI == null) {
                        System.out.println("OCSP URL is reqired if a serial number is used.");
                        System.exit(-1); // NOPMD, it's not a JEE app
                    }
                    final OCSPUnidClient client = OCSPUnidClient
                            .getOCSPUnidClient(ksfilename, kspwd, ocspUrlFromCLI, signRequest, ksfilename != null);
                    response = client.lookup(new BigInteger(certfilename, 16), getCertFromPemFile(cacertfilename), useGet);
                } catch (NumberFormatException e) {
                    // Not a hex serial number
                    System.out.println("The input that looked like a serial number was not one, try to read it as a file.");
                }
            }
            if (serial == null) {
                // It's not a certificate serial number, so treat it as a filename
                final Certificate userCert = getCertFromPemFile(certfilename);
                String ocspUrl = ocspUrlFromCLI;
                if (ocspUrl == null) {
                    ocspUrl = CertTools.getAuthorityInformationAccessOcspUrl(userCert);
                    if (ocspUrl == null) {
                        System.out.println("OCSP URL is required since none was found in the certificate.");
                        System.exit(-1); // NOPMD, it's not a JEE app
                    }
                }
                final OCSPUnidClient client = OCSPUnidClient.getOCSPUnidClient(ksfilename, kspwd, ocspUrl, signRequest, true);
                response = client.lookup(userCert, getCertFromPemFile(cacertfilename), useGet);
            }
            if (response.getErrorCode() != OCSPUnidResponse.ERROR_NO_ERROR) {
                System.out.println("Error querying OCSP server.");
                System.out.println("Error code is: " + response.getErrorCode());
            }
            if (response.getHttpReturnCode() != 200) {
                System.out.println("Http return code is: " + response.getHttpReturnCode());
            }
            if (response.getResponseStatus() == 0) {
                System.out.print("OCSP return value is: " + response.getStatus() + " (");
                switch (response.getStatus()) {
                case OCSPUnidResponse.OCSP_GOOD:
                    System.out.println("good)");
                    break;
                case OCSPUnidResponse.OCSP_REVOKED:
                    System.out.println("revoked)");
                    break;
                case OCSPUnidResponse.OCSP_UNKNOWN:
                    System.out.println("unknown)");
                    break;
                }
                System.out.println("producedAt: " + response.getProducedAt() + "  thisUpdate: " + response.getThisUpdate() + "  nextUpdate: "
                        + response.getNextUpdate());
                if (response.getFnr() != null) {
                    System.out.println("Returned Fnr is: " + response.getFnr());
                }
            } else {
                System.out.print("OCSP response status is: " + response.getResponseStatus() + " (");
                switch (response.getResponseStatus()) {
                case OCSPRespBuilder.MALFORMED_REQUEST:
                    System.out.println("malformed request)");
                    break;
                case OCSPRespBuilder.INTERNAL_ERROR:
                    System.out.println("internal error");
                    break;
                case OCSPRespBuilder.TRY_LATER:
                    System.out.println("try later)");
                    break;
                case OCSPRespBuilder.SIG_REQUIRED:
                    System.out.println("signature required)");
                    break;
                case OCSPRespBuilder.UNAUTHORIZED:
                    System.out.println("unauthorized)");
                    break;
                }
            }
        } catch( SecurityException e ) {
            throw e; // System.exit() called. Not thrown in normal operation but thrown by the custom SecurityManager when clientToolBoxTest is executed. Must not be caught.
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1); // NOPMD, it's not a JEE app
        }
    }

    /**
     * @param args command line arguments
     */
    public static void main(String[] args) {
        final List<String> lArgs = new ArrayList<String>();
        lArgs.add("dummy");
        for (int i = 0; i < args.length; i++) { // remove first argument
            lArgs.add(args[i]);
        }
        new Ocsp().execute(lArgs.toArray(new String[] {}));
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    protected String getName() {
        return "OCSP";
    }
}
