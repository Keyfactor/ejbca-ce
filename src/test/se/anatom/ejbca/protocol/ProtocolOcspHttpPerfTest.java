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

package se.anatom.ejbca.protocol;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Random;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/** Tests http pages of a standalone ocsp
 * To run this test you must create a user named ocspTest that has at least two certificates and
 * at least one of them must be revoked.
 * 
 * Change the adress 127.0.0.1 to where you standalone OCSP server is running.
 * Change caid to the CA that ocspTest blongs to
 **/
public class ProtocolOcspHttpPerfTest extends TestCase {
    private static final Logger log = Logger.getLogger(ProtocolOcspHttpPerfTest.class);

    //private static final String myOcspIp = "127.0.0.1";
    private static final String myOcspIp = "192.168.1.111";
    private static final String httpReqPath = "http://"+myOcspIp+":8080/ejbca";
    private static final String resourceOcsp = "publicweb/status/ocsp";
    private static X509Certificate cacert = null;
    private static X509Certificate tomastest = null;
    
    // For getting random serial numbers
    private static String sernofile = "/home/tomas/sernos.txt";
	private static ArrayList sernos = new ArrayList();
    private static Random random = new Random();
    private static int sernosize;
    
    // For signing requests
    private static String signerp12 = "/home/tomas/dev/ocsp-perftest/tomas_test.p12";
    private static String signingAlg = "SHA1WithRSA";
    private static X509Certificate[] certChain;
    private static PrivateKey privKey;
    private static String alias = "Tomas Test";
    private static String ksPwd = "foo123";
    
    private static byte[] _cacertbytes = Base64.decode(("MIIDXTCCAkWgAwIBAgIIccgXBw1L0TIwDQYJKoZIhvcNAQEFBQAwPDERMA8GA1UE"
+"AwwIQWRtaW5DQTExGjAYBgNVBAoMEUVKQkNBIFRvbWFzTGFwdG9wMQswCQYDVQQG"
+"EwJTRTAeFw0wNzAyMjcxNjA5MjlaFw0xNzAyMjQxNjA5MjlaMDwxETAPBgNVBAMM"
+"CEFkbWluQ0ExMRowGAYDVQQKDBFFSkJDQSBUb21hc0xhcHRvcDELMAkGA1UEBhMC"
+"U0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCJqRoUqDAy+4n/s8tb"
+"tSpLsJjGSTVbLoDdVuexL7LxoGzktRE0j1/G5KbaC97wFP3VmMVSq7yZ4Gu3TpVR"
+"mod3oVnerU++GA/GajIv7Aw4HSxXG7gLZJ3i7rbSorXeCskhPEqR0aP68HnSbB1m"
+"cuag3nHhqJgdx79JebMFBROJx+vPM1A6u7mPHZ56R5PFtbhCpp2CqiTGCrlDqXFW"
+"2oAB/fgpTvhCtHxljkKWgW2zFCckYrCgVgDTv+4lR/lFiS3N7qtf+Ex7n9zWlcgl"
+"w6lFJrxsnSf8g74YQAWuSd8q14ImTmdyvzeiRuLY+N9porjYlHK+Qz2Xwe11IUqb"
+"xKqFAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0G"
+"A1UdDgQWBBS8vyLgYrlXRWm9kLaYvMK2D7ribTAfBgNVHSMEGDAWgBS8vyLgYrlX"
+"RWm9kLaYvMK2D7ribTANBgkqhkiG9w0BAQUFAAOCAQEAb6p7+2VN28EpnvDop0Z2"
+"M10NtpY9PpX19uYF6DuhY2LUtXVPZiqDeyeWqy974D/yu0HUoLZjGHfcDl8TdMS3"
+"afNM8hhDm04cTMkThe+wV1UZk8icg084np9Ntg8p8c2hq+RTF3BVNfjGWbDgCoZu"
+"5x92+jk1umcH/MlAmTl/fQvUHw0LLodTVQDaQPGKyj5echUo4NxqEwZkj1pML8sx"
+"g1hwyTrLmc0/hzhj8al7I4RMm5nHp87A0pvnNSDE5Pn6pQLPsDNFwbJ3oPF0m1ag"
+"8hPt9shRmWpwCsLBnZLKGyqm9dv+iyO240fKXbouvbIM+kIgLdYq5y8uwm10YKby"
+"SA==").getBytes());

    private static byte[] cacertbytes = Base64.decode(("MIIDUzCCAjugAwIBAgIIYaMOuWb2DfEwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
+"AwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
+"HhcNMDcwMzI3MDkyMDAwWhcNMTcwMzI0MDkyMDAwWjA3MREwDwYDVQQDDAhBZG1p"
+"bkNBMTEVMBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRTCCASIwDQYJ"
+"KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOQAijHm1XqQi9VCBJQgo7KkXRzkp5ZO"
+"vRBgpj+BB2lUT/3EHWvvCtWtMHxZdIlBu8+2IpT4MDUSp92/fguYrw7AiWyId187"
+"26GOVGjTHPNxp2+GV91Cxdo8RPQArOP7x6yTGfW8sCDtd4P8Y+Mriw8tccgUv4ft"
+"HT6BtRyYSU10KvWyxlcqrtJFifZsqQA0PRv8Wk32rOHdwCCDjX+G5Tq5eIXatvEf"
+"lkl1oncpdjf0U8DpOHDK8ROoOEk74VdZm3tShGVZGZuXEenu84CQOZS48XOBe4Ar"
+"ZDsLMBoEjuZoXpqZkRIQmbm+zanDo/lbZcukbjJlsjk+oAmFjGKj0RMCAwEAAaNj"
+"MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFA/A"
+"R/2fwaEKCXYTEMgOxa/s4ZPqMB8GA1UdIwQYMBaAFA/AR/2fwaEKCXYTEMgOxa/s"
+"4ZPqMA0GCSqGSIb3DQEBBQUAA4IBAQAlU1G9IxfWkkWuUcK7wC5L1Dt7tOYv4kD8"
+"PD3MhoqYyRMZBXfLEKqzk2xQArmlSKhdLbTLc+UTjFQOrZLgdETH1yvKSQVEy7yO"
+"u01oBMA8MjpdvdNjMifyubMUWW76H1mfQugXvBanNwxPS36Jh7zW2nugDm5eOrHs"
+"eBTSJodEdfwAq64Q7S3KGJg2TnhxkZFiylheHKo69mD2/MV7lxNGw8Ov7y2jCfu9"
+"FiWCdy5RrCfNSK9eswXQXcCWfH4gdNImISbELUmoJNTG4EeLBO/RPYgNe6CjXgFl"
+"35L8c21PwP1yzSBaLc0bwiTtwi4cF3pzTEEJWVIFJxocwHPi8AKH").getBytes());
    
    private static byte[] _tomastestbytes = Base64.decode(("MIIDHzCCAgegAwIBAgIIAN2FDji8AMAwDQYJKoZIhvcNAQEFBQAwPDERMA8GA1UE"
+"AwwIQWRtaW5DQTExGjAYBgNVBAoMEUVKQkNBIFRvbWFzTGFwdG9wMQswCQYDVQQG"
+"EwJTRTAeFw0wNzA0MTcxNDAzMjhaFw0wOTA0MTYxNDEzMjhaMEoxGjAYBgkqhkiG"
+"9w0BCQEWC2RjMUBmb28uY29tMQwwCgYDVQQDDANkYzExETAPBgNVBAoMCFByaW1l"
+"S2V5MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtuDh"
+"bkd8BglwhRbczlrpWjnS1w4hVCJVT9ptioFmHRnYGBpsmZdlxhq+lBFKEQgfR2nu"
+"xuHzPo5DoOODj3OLn0TuH7URkOU2zFlyzKB5PKBTbQvBUwB2Vsu35pjaDP8eXy6g"
+"ivpqb4SM3jh8GTsPnDFm+Gk2YuIGViYsI9gqpwUCAwEAAaOBmjCBlzAMBgNVHRMB"
+"Af8EAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQUdSxlbaGZNdwaFbxXdNVX"
+"QNkWTCowHwYDVR0jBBgwFoAUvL8i4GK5V0VpvZC2mLzCtg+64m0wFgYDVR0RBA8w"
+"DYELZGMxQGZvby5jb20wHwYJKwYBBAGCNxQCBBIWEERvbWFpbkNvbnRyb2xsZXIw"
+"DQYJKoZIhvcNAQEFBQADggEBAHp40JkyUsldrTS3QzHhRIKUsx9ewgGbYPCt/1jS"
+"5/cjb/Szp6+ttfKW4FiH5ekZgRDYK+1AxRH9EVIu/CkYvD28qsHPWgBi+NA9AvC6"
+"s9sDPt/RIAUnD+0wXI9GYnia8QJIC78j3XTJy/5TiKyS14uaE4pJIs0fnIfqxWYz"
+"nIUIZIjBzL5JMkZ8pc7hX5NfstfIKslTJhed0hUav7Hqe2SX07vJIieHgGnBVnnA"
+"hNO8LYRNF27pE+hwFbA8AHv6MLfB5YFIrlfmrgTyWXloSzLXibtNocxLY5KU3N8Y"
+"F4gxtx2HFCfK+eGRh73p2t2wZ1m9aO+epjPxfEKwCO9+z1I=").getBytes());

    private static byte[] tomastestbytes = Base64.decode(("MIIDhTCCAm2gAwIBAgIIBBjzu9nuz7gwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
+"AwwIQWRtaW5DQTExFTATBgNVBAoMDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
+"HhcNMDcwMzI3MDkxMDA4WhcNMDkwMzI2MDkyMDA4WjBXMR4wHAYDVQQDDBVPQ1NQ"
+"U2lnbmVyQ2VydGlmaWNhdGUxETAPBgNVBAMMCEFkbWluQ0ExMRUwEwYDVQQKDAxF"
+"SkJDQSBTYW1wbGUxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
+"MIIBCgKCAQEA7hxZJWZTL6u2ha5MJQbCnYPfX3trJtHtQu5Tf0PE53oXu70+MKc9"
+"OFcXjj9TiUhyIfraTwc/WEW8aSl89ilpP9AAQeBGcx9TEfE8ZvYJqT9j3qSGbNzT"
+"l0Z7ZjgQ8B6r0siMM93eV3myf6g0vIuthoA0D7TJE1SoIQO+1gLGK4P0ChkJKCNz"
+"oZuY5y5V6njtAbg9Jane1AwAT090o+NCBDAfQUgNZKo7yQ7FlONkUuhR3DPXVU85"
+"arzp/NEB7UzaSJhkZMZgfTQIa4pJ+A8+S5YmzcwZUz5VWjd3GNYV4v92qXZbHSAt"
+"5ZNeakXEP9ifsaAqXeNvgZbtD7WrskGwtwIDAQABo3UwczAMBgNVHRMBAf8EAjAA"
+"MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDCTAdBgNVHQ4EFgQU"
+"wcHrtaL7Hx6/MlvfV1WPcOF0bpEwHwYDVR0jBBgwFoAUD8BH/Z/BoQoJdhMQyA7F"
+"r+zhk+owDQYJKoZIhvcNAQEFBQADggEBADPKhS2l266fOUzXrQWnvlkBCVqWK9QG"
+"S3UFB5nYsEtVKbEakrq8qDLjc7arcRrQ5oPd/Nb1wjQRWfH5yqgUDjzJ/uDSCaXl"
+"KPTwWlSSoERF+wSlptn9Ldle/n+dSmQHIxpqUg+6TAQFy6tPIyLXk/JYA/UyeSEQ"
+"JYmKN5hy9liG5a0ADnVNRhL0zqRnO528OONgPUwri21ks0iW2L37nymQxa2EsgX3"
+"Aw/k+uhfL1aW01jlXEMolz7+3cmAgw0lWAGImD5HG2g7zgcHGVNSd15aWYU6Gqp/"
+"JV+mNkD7qQ+bUaRUj7eStN8Vy6E7DHr7Ir3ghKs0RBary544CK+LxRU=").getBytes());
    
    public ProtocolOcspHttpPerfTest(String name) throws Exception {
        super(name);
        CertTools.installBCProvider();
    	cacert = CertTools.getCertfromByteArray(cacertbytes);
    	tomastest = CertTools.getCertfromByteArray(tomastestbytes);
    	
    	// Read sernos.txt into a nice map
    	BufferedReader in = new BufferedReader(new FileReader(sernofile));
    	String instr = null;
    	while (in.ready()) {
			instr = in.readLine();
			if (instr != null) {
				BigInteger bi = new BigInteger(instr);
				sernos.add(bi);
			}
    	}
    	sernosize = sernos.size();
    	KeyStore ks = KeyStore.getInstance("PKCS12");
    	FileInputStream fis = new java.io.FileInputStream(signerp12);
        ks.load(fis, ksPwd.toCharArray());
    	privKey = (PrivateKey)ks.getKey(alias, ksPwd.toCharArray());
    	Certificate[] chain = ks.getCertificateChain(alias);
    	certChain = new X509Certificate[chain.length];
    	for (int i=0; i<chain.length;i++) {
    		certChain[i] = (X509Certificate)chain[i];
    		System.out.println("Cert["+i+"] subject: "+certChain[i].getSubjectDN().getName());
    	}
    	
    }
    private static BigInteger getSerno() {
    	int i = random.nextInt(sernosize);
    	BigInteger ret = (BigInteger)sernos.get(i);
    	return ret;
    }
    
    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test01OcspGood() throws Exception {
        log.debug(">test02OcspGood()");

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        final X509Certificate ocspTestCert = getTestCert();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        gen.setRequestorName(certChain[0].getSubjectX500Principal());
        OCSPReq req = gen.generate(signingAlg, privKey, certChain, "BC");

        // Send the request and receive a singleResponse
        SingleResp singleResp = sendOCSPPost(req.getEncoded(), null);
        
        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
        log.debug("<test02OcspGood()");
    }
    
    
    public void test03MakeLotsOfReqs() throws Exception {
		long before = System.currentTimeMillis();
        Thread no1 = new Thread(new OcspTester(),"no1");
        Thread no2 = new Thread(new OcspTester(),"no2");
        Thread no3 = new Thread(new OcspTester(),"no3");
        Thread no4 = new Thread(new OcspTester(),"no4");
        Thread no5 = new Thread(new OcspTester(),"no5");
        Thread no6 = new Thread(new OcspTester(),"no6");
//        Thread no7 = new Thread(new OcspTester(),"no7");
//        Thread no8 = new Thread(new OcspTester(),"no8");
//        Thread no9 = new Thread(new OcspTester(),"no9");
//        Thread no10 = new Thread(new OcspTester(),"no10");
        no1.start();
        System.out.println("Started no1");
        no2.start();
        System.out.println("Started no2");
        no3.start();
        System.out.println("Started no3");
        no4.start();
        System.out.println("Started no4");
        no5.start();
        System.out.println("Started no5");
        no6.start();
        System.out.println("Started no6");
//        no7.start();
//        System.out.println("Started no7");
//        no8.start();
//        System.out.println("Started no8");
//        no9.start();
//        System.out.println("Started no9");
//        no10.start();
//        System.out.println("Started no10");
        no1.join();
        no2.join();
        no3.join();
        no4.join();
        no5.join();
        no6.join();
//        no7.join();
//        no8.join();
//        no9.join();
//        no10.join();
		long after = System.currentTimeMillis();
		long diff = after - before;
        System.out.println("All threads finished. Total time: "+diff);
    }
    

    // 
    // Private helper methods
    //
    private class OcspTester implements Runnable {
    	public void run() {
            try {
				long before = System.currentTimeMillis();
				for (int i = 0; i<1000;i++) {
			        // And an OCSP request
			        OCSPReqGenerator gen = new OCSPReqGenerator();
			        //final X509Certificate ocspTestCert = getTestCert();
			        BigInteger serno = getSerno();
			        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, serno));
			        gen.setRequestorName(certChain[0].getSubjectX500Principal());
			        OCSPReq req = gen.generate(signingAlg, privKey, certChain, "BC");

			        // Send the request and receive a singleResponse
			        SingleResp singleResp = sendOCSPPost(req.getEncoded(), null);
			        
			        CertificateID certId = singleResp.getCertID();
			        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), serno);
			        Object status = singleResp.getCertStatus();
			        assertEquals("Status is not null (good)", status, null);
			        
				    if ((i % 100) == 0) {
				    	long mellantid = System.currentTimeMillis() - before;
				    	System.out.println(Thread.currentThread().getName()+" har gjort "+i+" requests, tid="+mellantid);
				    }
				}
				long after = System.currentTimeMillis();
				long diff = after - before;
				System.out.println("Tidsåtgång ("+Thread.currentThread().getName()+"): "+diff);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}    		
    	}
    }
    
    private X509Certificate getTestCert( ) {
    	return tomastest;
    }

    private SingleResp sendOCSPPost(byte[] ocspPackage, String nonce) throws IOException, OCSPException, NoSuchProviderException {
        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceOcsp);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = con.getOutputStream();
        os.write(ocspPackage);
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "application/ocsp-response", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and OCSP requests are small
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(respBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        X509Certificate[] chain = brep.getCerts("BC");
        boolean verify = brep.verify(chain[0].getPublicKey(), "BC");
        assertTrue("Response failed to verify.", verify);
        // Check nonce (if we sent one)
        if (nonce != null) {
        	byte[] noncerep = brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
        	assertNotNull(noncerep);
        	ASN1InputStream ain = new ASN1InputStream(noncerep);
        	ASN1OctetString oct = ASN1OctetString.getInstance(ain.readObject());
        	assertEquals(nonce, new String(oct.getOctets()));
        }
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", singleResps.length, 1);
        SingleResp singleResp = singleResps[0];
        return singleResp;
    }

}
