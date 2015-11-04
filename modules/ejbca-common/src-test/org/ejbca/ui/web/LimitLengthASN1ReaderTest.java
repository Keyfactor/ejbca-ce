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

package org.ejbca.ui.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.BERTags;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.junit.After;
import org.junit.Test;

/**
 * Series of unit tests for LimitLengthASN1Reader
 * 
 * @version $Id$
 */
public class LimitLengthASN1ReaderTest {

	private LimitLengthASN1Reader limitLengthASN1Reader;
	private InputStream inputStreamStub;

	/*
	 * The contents of this input stream are known to be a working ASN.1
	 * representation, since they have been lifted from a working environment.
	 */
	private static final int[] VALID_STREAM = { BERTags.SEQUENCE, 108, 48, 106,
			48, 69, 48, 67, 48, 65, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20,
			65, 69, -8, -91, -52, -16, 126, 1, -21, -15, -46, 45, 64, -95, -30,
			-109, -110, -79, -32, 46, 4, 20, 81, 9, 91, -19, -59, -104, 106,
			-32, 80, 42, -97, 88, -91, 88, -125, -50, -16, -43, -10, -101, 2,
			8, 121, 75, 2, 87, -86, 123, 29, 36, -94, 33, 48, 31, 48, 29, 6, 9,
			43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 16, -119, -46, 30, 7, -3, 61, 29,
			-107, 38, -27, -67, 106, -65, 50, -128, 105 };

	/*
	 * Length byte is longer than LimitLengthASN1Reader.MAX_REQUEST_SIZE
	 */
	private static final int[] INVALID_LENGTH = { BERTags.SEQUENCE, 0x18704,
			48, 106, 48, 69, 48, 67, 48, 65, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5,
			0, 4, 20, 65, 69, -8, -91, -52, -16, 126, 1, -21, -15, -46, 45, 64,
			-95, -30, -109, -110, -79, -32, 46, 4, 20, 81, 9, 91, -19, -59,
			-104, 106, -32, 80, 42, -97, 88, -91, 88, -125, -50, -16, -43, -10,
			-101, 2, 8, 121, 75, 2, 87, -86, 123, 29, 36, -94, 33, 48, 31, 48,
			29, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 16, -119, -46, 30, 7, -3,
			61, 29, -107, 38, -27, -67, 106, -65, 50, -128, 105 };

	/*
	 * This stream contains less bytes than specified. May be due to a broken
	 * connection.
	 */
	private static final int[] FINITE_STREAM_TOO_SHORT = { BERTags.SEQUENCE,
			108, 48, 106, 48, 69, 48, 67, 48, 65, 48, 9, 6, 5, 43, 14, 3, 2,
			26, 5, 0, 4, 20, 65, 69, -8, -91, -52, -16, 126, 1, -21, -15, -46,
			45, 64, -95, -30, -109, -110, -79, -32, 46, 4, 20, 81, 9, 91, -19,
			-59, -104, 106, -32, 80, 42, -97, 88, -91, 88, -125, -50, -16, -43,
			-10, -101, 2, 8, 121, 75, 2, 87, -86, 123, 29, 36, -94, 33, 48, 31,
			48, 29, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 16, -119, -46, 30, 7,
			-3, 61, 29, -107, 38, -27, -67, 106, -65, 50, -128 };

	/*
	 * Sequence byte has been replaced by an integer.
	 */
	private static final int[] NOT_A_SEQUENCE_STREAM = { BERTags.INTEGER, 108,
			48, 106, 48, 69, 48, 67, 48, 65, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5,
			0, 4, 20, 65, 69, -8, -91, -52, -16, 126, 1, -21, -15, -46, 45, 64,
			-95, -30, -109, -110, -79, -32, 46, 4, 20, 81, 9, 91, -19, -59,
			-104, 106, -32, 80, 42, -97, 88, -91, 88, -125, -50, -16, -43, -10,
			-101, 2, 8, 121, 75, 2, 87, -86, 123, 29, 36, -94, 33, 48, 31, 48,
			29, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 16, -119, -46, 30, 7, -3,
			61, 29, -107, 38, -27, -67, 106, -65, 50, -128, 105 };

	/*
	 * Represents an infinite length stream
	 */
	private static final int[] UNDEFINED_LENGTH_HAPPY = { BERTags.SEQUENCE,
			128, 48, 106, 48, 69, 48, 67, 48, 65, 48, 9, 6, 5, 43, 14, 3, 2,
			26, 5, 0, 4, 20, 65, 69, -8, -91, -52, -16, 126, 1, -21, -15, -46,
			45, 64, -95, -30, -109, -110, -79, -32, 46, 4, 20, 81, 9, 91, -19,
			-59, -104, 106, -32, 80, 42, -97, 88, -91, 88, -125, -50, -16, -43,
			-10, -101, 2, 8, 121, 75, 2, 87, -86, 123, 29, 36, -94, 33, 48, 31,
			48, 29, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 16, -119, -46, 30, 7,
			-3, 61, 29, -107, 38, -27, -67, 106, -65, 50, -128, 105 };



	@After
	public void tearDown() throws IOException {
		limitLengthASN1Reader = null;
		inputStreamStub.close();
	}

	/**
	 * Test happy path implementation of readFirstASN1Object.
	 */
    @Test
	public void testReadFirstASN1ObjectHappyPath() throws MalformedRequestException, IOException {
		inputStreamStub = new InputStreamStub(VALID_STREAM);
		limitLengthASN1Reader = new LimitLengthASN1Reader(inputStreamStub, VALID_STREAM.length);
		byte[] result = limitLengthASN1Reader.readFirstASN1Object();
		for (int i = 0; i < result.length; i++) {
			assertEquals("Value #" + i + " did not match expected output.", VALID_STREAM[i], result[i]);
		}
	}

	/**
	 * Attempts to process a stream which is incorrectly declared.
	 */
    @Test
	public void testReadFirstASN1ObjectNotASequence() throws IOException {
		inputStreamStub = new InputStreamStub(NOT_A_SEQUENCE_STREAM);
		limitLengthASN1Reader = new LimitLengthASN1Reader(inputStreamStub, NOT_A_SEQUENCE_STREAM.length);
		try {
			limitLengthASN1Reader.readFirstASN1Object();
			fail("MalformedRequestException should have been thrown.");
		} catch (MalformedRequestException e) {
		}
	}

	/**
	 * Tries to process a stream with size larger than specified limit. Sending
	 * a stream of infinite length may be part of a DOS attack.
	 */
    @Test
	public void testReadFirstASN1ObjectLargerThanMaxRequestSize() {
		inputStreamStub = new InputStreamStub(INVALID_LENGTH);
		limitLengthASN1Reader = new LimitLengthASN1Reader(inputStreamStub, 0);
		try {
			limitLengthASN1Reader.readFirstASN1Object();
		} catch (IOException e) {
			return;
		} catch (MalformedRequestException e) {
		}
		fail("IOException should have been thrown.");
	}

	/**
	 * Test readFirstASN1Object() with a stream that is missing it's last byte.
	 * Might be due to a broken connection.
	 */
    @Test
	public void testReadFirstASN1ObjectWithBrokenStream() throws IOException {
		inputStreamStub = new InputStreamStub(FINITE_STREAM_TOO_SHORT);
		limitLengthASN1Reader = new LimitLengthASN1Reader(inputStreamStub, 0);
		try {
			limitLengthASN1Reader.readFirstASN1Object();
			fail("MalformedRequestException should have been thrown.");
		} catch (MalformedRequestException e) {
		}
	}

	/**
	 * Test readFirstASN1Object() with a stream where there is no defined ASN1 object length  
	 */
    @Test
	public void testReadFirstASN1ObjectUndefinedLengthHappyPath() throws MalformedRequestException, IOException {
		inputStreamStub = new InputStreamStub(UNDEFINED_LENGTH_HAPPY);
		limitLengthASN1Reader = new LimitLengthASN1Reader(inputStreamStub, 108);
		byte[] result = limitLengthASN1Reader.readFirstASN1Object();
		for (int i = 2; i < result.length; i++) {
			assertEquals("Value #" + i + " did not match expected output.", UNDEFINED_LENGTH_HAPPY[i], result[i]);
		}
	}

	/**
	 * Test readFirstASN1Object() with a stream where there is no defined ASN1 object length and
	 * content is invalid.  
	 */
    @Test
	public void testReadFirstASN1ObjectUndefinedLengthAndInvalidContentLengthHappyPath() throws MalformedRequestException, IOException {
		inputStreamStub = new InputStreamStub(UNDEFINED_LENGTH_HAPPY);
		limitLengthASN1Reader = new LimitLengthASN1Reader(inputStreamStub, 1);
		byte[] result = limitLengthASN1Reader.readFirstASN1Object();
		for (int i = 2; i < result.length; i++) {
			assertEquals("Value #" + i + " did not match expected output.", UNDEFINED_LENGTH_HAPPY[i], result[i]);
		}
	}
	
	/**
	 * Private inner class which represents an input stream with controlled output.
	 * 
	 * TODO: When our test runner is reformed to only run tests matching
	 * **\*Test.class, make this an inner class to LimitLengthASN1ReaderTest
	 * 
	 */
	class InputStreamStub extends InputStream {

		private int[] contents;
		private int counter = 0;

		public InputStreamStub(int[] contents) {
			super();
			this.contents = contents;
		}

		public int read() throws IOException {
			if (contents == null) {
				throw new NullPointerException(
						"Class member contents must be set for anonymous inner class.");
			}
			if (counter < contents.length) {
				return contents[counter++];
			} else {
				return -1;
			}
		}
	}

}
