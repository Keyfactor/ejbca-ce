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
import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

/**
 * 
 * @version $Id$
 */
public class FixEndOfBrokenXMLTest extends TestCase {

	private static Logger log = Logger.getLogger(FixEndOfBrokenXMLTest.class);

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

	private void notPossibleToRemoveMoreBytes(int nrOfBytesMissing, byte brokenXml[]) {
		final int limit = 32;
		log.info("Repair tool not able to mend xml with "+nrOfBytesMissing+" missing chars in the end:");
		try {
			log.info(new String(brokenXml, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// do nothing
		}
		assertFalse("Only possible to fix "+nrOfBytesMissing+" missing bytes. We should be able to handle "+limit+" missing bytes.", nrOfBytesMissing<limit);
	}
	public void test01() throws Exception {
		final byte testXml[] = readXmlFromFile();
		// We need to decode and encode it with the current JDK we are running, 
		// because the JDK version is in the XML and different JDKs add different amount of whitespace
		byte[] xml = decodeAndEncode(testXml);		
		for ( int nrOfBytesMissing = 0; xml.length>nrOfBytesMissing; nrOfBytesMissing++ ) {
			final byte brokenXml[] = Arrays.copyOf(xml, xml.length-nrOfBytesMissing);
			final byte fixedXml[] = FixEndOfBrokenXML.fixXML(new String(brokenXml, "UTF-8"), "string", "</void></object></java>").getBytes("UTF-8");

			final XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(fixedXml));
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			final XMLEncoder encoder = new XMLEncoder(baos);
			try {
				encoder.writeObject(decoder.readObject());
				encoder.close();
			} catch( Throwable t ) {
				log.error("Exception: ", t);
				notPossibleToRemoveMoreBytes(nrOfBytesMissing, brokenXml);
				return;
			}
			final byte decodedXml[] = baos.toByteArray();
			int limit = 32;
			if ( !Arrays.equals(xml,decodedXml) ) {
				if (nrOfBytesMissing < limit) {
					assertEquals("Only possible to fix "+nrOfBytesMissing+" missing bytes. We should be able to handle "+limit+" missing bytes.", new String(xml), new String(decodedXml));
				}
				notPossibleToRemoveMoreBytes(nrOfBytesMissing, brokenXml);
				return;
			}
		}
	}

	private byte[] decodeAndEncode(final byte[] testXml) {
		final XMLDecoder dec = new XMLDecoder(new ByteArrayInputStream(testXml));
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		final XMLEncoder encoder = new XMLEncoder(baos);
		encoder.writeObject(dec.readObject());
		encoder.close();
		return baos.toByteArray();
	}
}
