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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.ejbca.core.model.InternalEjbcaResources;

/** Helper class used all bytes for the first ASN.1 object in the stream. 
 * Limits the size that is ever read to MAX_REQUEST_SIZE. This class is used for example to read requests from POSTs to servlets, 
 * when you want to make sure that you never read too many bytes that might have been sent by an attacker.
 * Can only be used to read ASN.1 sequences, will throw MalformedException if first tag is not a sequence.
 * Example usage:
 * <pre>
 * final ServletInputStream in = request.getInputStream(); // ServletInputStream does not have to be closed, container handles this
 * ret = new LimitLengthASN1Reader(in, n).readFirstASN1Object();
 * </pre>
 * 
 * @version $Id$
 */
public class LimitLengthASN1Reader extends ASN1InputStream {

	private static final Logger m_log = Logger.getLogger(LimitLengthASN1Reader.class);
	/** Internal localization of logs and errors */
	private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

	/** Max size of a request is 100000 bytes */
	public static final int MAX_REQUEST_SIZE = 100000;
	
	private ByteArrayOutputStream baos;

	final private int contentLength; 
	/**
	 * 
	 * @param input
	 * @param contentLength the provided contentLength, we do not trust it but will use it if given
	 */
	public LimitLengthASN1Reader(final InputStream input, final int contentLength) {
		super(input, MAX_REQUEST_SIZE);
		this.baos = new ByteArrayOutputStream();
		this.contentLength = contentLength;
	}
	/* (non-Javadoc)
	 * @see java.io.FilterInputStream#read()
	 * This method is used in #readLeangth()
	 */
	@Override
	public int read() throws IOException {
		final int result = super.read();
		this.baos.write(result);
		return result;
	}
	/**
	 * Read the 'value' of the top ASN1 object and append it to the already read 'tag' and 'value'
	 * @param length nr of value bytes that we should read
	 * @return the top ASN1 object
	 * @throws IOException
	 * @throws MalformedRequestException if the number of bytes read is less than length, i.e. asn.1 length tag was invalid
	 */
	private byte[] readTopASN1(final int length) throws IOException, MalformedRequestException {
        // This small code snippet is inspired/copied from apache IO utils by Tomas Gustavsson...
        final byte[] buf = new byte[length]; // buf of length length, normal optimal case is only one read operation below
        int n = 0;
        int bytesRead = 0;
        // We must always read until it returns -1, make sure we read maximum length bytes
        while (-1 != (n = read(buf, 0, length-bytesRead))) {
            bytesRead += n;
            this.baos.write(buf, 0, n);
            if (bytesRead >= length) {
                // We read as much as we should, stop reading
                break;
            }
        }
        if (bytesRead != length) {
            // If we have read less bytes than we should have, the asn.1 was incorrect and this might be some type of attempt to perform buffer overflow
            final String msg = intres.getLocalizedMessage("request.notcorrectasn1length", Integer.valueOf(length), Integer.valueOf(bytesRead));
            m_log.info(msg);
            throw new MalformedRequestException(msg);
        }
        this.baos.flush();
        return this.baos.toByteArray();
	}

	/** Reads all bytes for the first ASN.1 object in the stream. Limits the size that is ever read to MAX_REQUEST_SIZE.
	 * @return all bytes for the first ASN.1 object in the stream. 
	 * @throws IOException
	 * @throws MalformedRequestException if the request is too large or not correctly GET encoded.
	 */
	public byte[] readFirstASN1Object() throws IOException, MalformedRequestException {
		final int tag = read() & 0x1f;
		if (tag != SEQUENCE) {
			final String msg = intres.getLocalizedMessage("request.notasequence", Integer.valueOf(tag));
			m_log.info(msg);
			throw new MalformedRequestException(msg);
		}
		final int length = readLength();
		if (length > MAX_REQUEST_SIZE) {
			final String msg = intres.getLocalizedMessage("request.toolarge", Integer.valueOf(MAX_REQUEST_SIZE), Integer.valueOf(length));
			m_log.info(msg);
			throw new MalformedRequestException(msg);
		}
		// If there was an asn.1 stream of undefined length we will try to read it the classic way, limiting the size of bytes read.
		if (length < 0) {// undefined length
			if (this.contentLength > MAX_REQUEST_SIZE) {
				final String msg = intres.getLocalizedMessage("request.toolarge", Integer.valueOf(MAX_REQUEST_SIZE), Integer.valueOf(this.baos.size()));
				m_log.info(msg);
				throw new MalformedRequestException(msg);
			}
			final int tlByteLength = this.baos.toByteArray().length;
			if (this.contentLength < tlByteLength) { // Content-length invalid. Try to read although.
				if (m_log.isTraceEnabled()) {
					m_log.trace("No content-length, reading as much as we have (<MAX_REQUEST_SIZE)");
				}
				final byte[] t = new byte[10240];
				int r = 0;
				int len = 0;
				while ( ((len = read(t)) != -1) && (r < LimitLengthASN1Reader.MAX_REQUEST_SIZE) ) { // never read more than MAX_OCSP_REQUEST_SIZE bytes
					this.baos.write(t, 0, len);
					r = r + len;
				}
				return this.baos.toByteArray();
			}
			// Read content-length bytes from stream
			if (m_log.isTraceEnabled()) {
				m_log.trace("Got content-length: "+this.contentLength);
			}
			return readTopASN1(this.contentLength-tlByteLength); // 'tlByteLength' bytes already read. 'this.contentLength <= MAX_REQUEST_SIZE' tested above.
		}
		// defined length, just read as many bytes as the length tag says
		if (m_log.isTraceEnabled()) {
			m_log.trace("Got ASN1 length: "+length);
		}
		return readTopASN1(length);
	}
}
