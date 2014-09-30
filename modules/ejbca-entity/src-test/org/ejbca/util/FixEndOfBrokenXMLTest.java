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
package org.ejbca.util;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test reparation of XML serialized objects.
 * 
 * @version $Id$
 */
public class FixEndOfBrokenXMLTest {

	private static Logger log = Logger.getLogger(FixEndOfBrokenXMLTest.class);
	private static String CHAR_ENCODING = "UTF-8";

	/**
	 * This test will take a XML serialized object and try to repair the end of it
	 * with a known String. It depends on the external file "test.xml".
	 * 
	 * This test does not reproduce the production failure that the fix was written
	 * for, but instead tests the general ability to repair XML under the current JDK.
	 */ 
	@Test
	public void test01() throws Exception {
		log.trace(">test01");
		final int limit = "</string></void></object></java>".length(); // This is what we expect to be able to repair
		final byte testXml[] = readXmlFromFile();
		// We need to decode and encode it with the current JDK we are running, 
		// because the JDK version is in the XML and different JDKs add different amount of whitespace
		byte[] xml = decodeAndEncode(testXml);
		for ( int nrOfBytesMissing = 0; xml.length>nrOfBytesMissing; nrOfBytesMissing++ ) {
			final byte brokenXml[] = Arrays.copyOf(xml, xml.length-nrOfBytesMissing);
			final byte fixedXml[] = FixEndOfBrokenXML.fixXML(new String(brokenXml, CHAR_ENCODING), "string", "</void></object></java>").getBytes(CHAR_ENCODING);

			final XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(fixedXml));
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			final XMLEncoder encoder = new XMLEncoder(baos);
            try {
                try {
                    encoder.writeObject(decoder.readObject());
                } catch (Throwable t) {
                    log.error("Exception: ", t);
                    notPossibleToRemoveMoreBytes(nrOfBytesMissing, brokenXml, limit);
                    return;
                } finally {
                    encoder.close();
                }
            } finally {
                decoder.close();
            }
			final byte decodedXml[] = baos.toByteArray();
			if ( !Arrays.equals(xml,decodedXml) ) {
				if (nrOfBytesMissing < limit) {
					assertEquals("Only possible to fix "+nrOfBytesMissing+" missing bytes. We should be able to handle "+limit+" missing bytes.", new String(xml), new String(decodedXml));
				}
				notPossibleToRemoveMoreBytes(nrOfBytesMissing, brokenXml, limit);
				return;
			}
		}
		log.trace("<test01");
	}

	private byte[] readXmlFromFile() throws IOException {
		final InputStream is = FixEndOfBrokenXMLTest.class.getResourceAsStream("test.xml");
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		while( true ) {
			final int available = is.available();
			if ( available>0 ) {
				final byte tmp[] = new byte[available];
				is.read(tmp);
				baos.write(tmp);
				continue;
			}
			final int tmp = is.read();
			if ( tmp<0 ) {
				break;
			}
			baos.write(tmp);
		}
		return baos.toByteArray();
	}

	private void notPossibleToRemoveMoreBytes(int nrOfBytesMissing, byte brokenXml[], final int limit) throws UnsupportedEncodingException {
		log.info("Repair tool not able to mend xml with "+nrOfBytesMissing+" missing chars in the end:\n" + new String(brokenXml, CHAR_ENCODING));
		assertFalse("Only possible to fix "+nrOfBytesMissing+" missing bytes. We should be able to handle "+limit+" missing bytes.", nrOfBytesMissing<limit);
	}

    private byte[] decodeAndEncode(final byte[] testXml) {
        final XMLDecoder dec = new XMLDecoder(new ByteArrayInputStream(testXml));
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            final XMLEncoder encoder = new XMLEncoder(baos);
            try {
                encoder.writeObject(dec.readObject());
            } finally {
                encoder.close();
            }
        } finally {
            dec.close();
        }
        return baos.toByteArray();
    }

	/**
	 * If the start of the last string-element is broken, we will remove all
	 * elements after the last valid closing string-element.
	 * 
	 * This might not be a good thing since we loose more data than necessary,
	 * but at least we want to have this behavior demonstrated and documented.
	 */
	@Test
	public void test02MissingLastStartOfString() throws Exception {
		log.trace(">test02MissingLastStartOfString");
		final String BROKEN_XML_2_PART1 =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0_18\" class=\"java.beans.XMLDecoder\">"
			+ "<object class=\"org.cesecore.certificates.endentity.EndEntityInformation\">"
			// ...
			+ "<void property=\"email\"><string>null@null.com</string></void>";
			// ...
		final String BROKEN_XML_2_PART2 =
			"<void property=\"type\"><int>1</int></void>"
			+ "<void property=\"username\"><strin";	// "Broken": "g>10022428256</string></void></object></java>";
		final String toFix = new String((BROKEN_XML_2_PART1+BROKEN_XML_2_PART2).getBytes(CHAR_ENCODING));
		final String fixed = new String(FixEndOfBrokenXML.fixXML(toFix, "string", "</void></object></java>").getBytes(CHAR_ENCODING), CHAR_ENCODING);
		final String expected = BROKEN_XML_2_PART1 + "</object></java>";
		log.info("toFix:    " + toFix);
		log.info("fixed:    " + fixed);
		log.info("expected: " + expected);
		assertEquals("XMLFix has chnaged behaviour. Did not remove objects as originally designed.", expected, fixed);
		log.trace("<test02MissingLastStartOfString");
	}
}
