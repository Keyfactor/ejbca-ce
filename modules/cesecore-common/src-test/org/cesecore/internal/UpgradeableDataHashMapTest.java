package org.cesecore.internal;

import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.lang.Thread.State;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * @version $Id$ 
 */
public class UpgradeableDataHashMapTest {
    
    static final Logger log = Logger.getLogger(UpgradeableDataHashMapTest.class);
    
    /**
     * Test if UpgradeableDataHashMap is vulnerable to CVE-2010-4476 through
     * the XML Serialization we use for storing UpgradeableDataHashMap.
     * 
     * When "2.2250738585072012e-308" is converted to a float, the code toggles
     * between two values causing the the Thread to hang.
     * 
     * UpgradeableDataHashMap.VERSION is normally stored as a Float.
     */
    @Test
    public void testCVE_2010_4476() {
        final String XML_W_BADFLOAT = "<java version=\"1.6.0_21\" class=\"java.beans.XMLDecoder\">"
            + "<object class=\"java.util.HashMap\"><void method=\"put\">"
            + "<string>version</string><float>2.2250738585072012e-308</float>"
            + "</void></object></java>";
        final String XML_W_BADDERFLOAT = "<java version=\"1.6.0_21\" class=\"java.beans.XMLDecoder\">"
            + "<object class=\"java.util.HashMap\"><void method=\"put\">"
            + "<string>version</string><double>2.2250738585072012e-308</double>"
            + "</void></object></java>";
        final String FAIL_MESSAGE = "JDK is vulnerable to CVE-2010-4476 (requires write access to EJBCA database to exploit).";
        assertTrue(FAIL_MESSAGE, new DecoderThread(XML_W_BADFLOAT).execute());
        assertTrue(FAIL_MESSAGE, new DecoderThread(XML_W_BADDERFLOAT).execute());
    }
    
    /** Separate thread for test that might hang. */
    class DecoderThread implements Runnable {   // NOPMD this is a stand-alone test, not a part of a JEE application
        final String decodeXML;

        DecoderThread(String decodeXML) {
            this.decodeXML = decodeXML;
        }
        
        protected boolean execute() {
            Thread t = new Thread(this);    // NOPMD this is a stand-alone test, not a part of a JEE application
            t.start();
            try {
                t.join(4000);   //Wait 5 seconds for thread to complete
            } catch (InterruptedException e) {
                e.printStackTrace();
            } 
            if (!t.getState().equals(State.TERMINATED)) {
                t.interrupt();
                return false;
            }
            return true;
        }

        @SuppressWarnings("unchecked")
        @Override
        public void run() {
            try {
                final java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(decodeXML.getBytes("UTF8")));
                final HashMap<Object,Object> h = (HashMap<Object,Object>) decoder.readObject();
                decoder.close();
                for (Object o : h.keySet()) {
                    log.info(o.toString() + ": " + h.get(o));
                }
            } catch (UnsupportedEncodingException e) {
                log.error("",e);
            }
        }
    }
}
