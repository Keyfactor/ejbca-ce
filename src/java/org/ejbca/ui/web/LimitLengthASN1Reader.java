package org.ejbca.ui.web;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.MalformedRequestException;

/** Helper class used all bytes for the first ASN.1 object in the stream. 
 * Limits the size that is ever read to MAX_REQUEST_SIZE. This class is used for example to read requests from POSTs to servlets, 
 * when you want to make sure that you never read too many bytes that might have been sent by an attacker.
 * Can only be used to read ASN.1 sequences, will throw MalformedException if first tag is not a sequence.
 * Example usage:
 * <pre>
 * final ServletInputStream in = request.getInputStream(); // ServletInputStream does not have to be closed, container handles this
 * ret = new LimitLengthServletPostReader(in, n).readFirstASN1Object();
 * </pre>
 */
public class LimitLengthASN1Reader extends ASN1InputStream {

	private static final Logger m_log = Logger.getLogger(LimitLengthASN1Reader.class);
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	/** Max size of a request is 100000 bytes */
	public static final int MAX_REQUEST_SIZE = 100000;
	
	private ByteArrayOutputStream baos;

	final private int contentLength; 
	/**
	 * 
	 * @param input
	 * @param contentLength the provided contentLength, we do not trust it but will use it if given
	 */
	public LimitLengthASN1Reader(InputStream input, int contentLength) {
		super(input);
		this.contentLength = contentLength;
	}
	/* (non-Javadoc)
	 * @see java.io.FilterInputStream#read()
	 * This method is used in #readLeangth()
	 */
	public int read() throws IOException {
		final int result = super.read();
		this.baos.write(result);
		return result;
	}
	/**
	 * Read the 'value' of the top ASN1 object and append it to the already read 'tag' and 'value'
	 * @param length nr of value bytes
	 * @return the top ASN1 object
	 * @throws IOException
	 * @throws MalformedRequestException
	 */
	private byte[] readTopASN1(int length) throws IOException, MalformedRequestException {
		final byte value[] = new byte[length];
		final int readLength = read(value);
		if ( readLength != length ) {
			final String msg = intres.getLocalizedMessage("request.notcorrectasn1length", new Integer(length), new Integer(readLength));
			m_log.info(msg);
			throw new MalformedRequestException(msg);
		}
		this.baos.write(value);
		this.baos.flush();
		return this.baos.toByteArray();			
	}
	/** Reads all bytes for the first ASN.1 object in the stream. Limits the size that is ever read to MAX_REQUEST_SIZE.
	 * @return all bytes for the first ASN.1 object in the stream. 
	 * @throws IOException
	 * @throws MalformedRequestException if the request is too large or not correctly GET encoded.
	 */
	public byte[] readFirstASN1Object() throws IOException, MalformedRequestException {
		this.baos = new ByteArrayOutputStream();
		final int tag = read() & 0x1f;
		if (tag != SEQUENCE) {
			final String msg = intres.getLocalizedMessage("request.notasequence", new Integer(tag));
			m_log.info(msg);
			throw new MalformedRequestException(msg);
		}
		final int length = readLength();
		if (length > MAX_REQUEST_SIZE) {
			final String msg = intres.getLocalizedMessage("request.toolarge", new Integer(MAX_REQUEST_SIZE), new Integer(length));
			m_log.info(msg);
			throw new MalformedRequestException(msg);
		}
		// If there was an asn.1 stream of undefined length we will try to read it the classic way, limiting the size of bytes read.
		if (length < 0) {// undefined length
			if (this.contentLength > MAX_REQUEST_SIZE) {
				final String msg = intres.getLocalizedMessage("request.toolarge", new Integer(MAX_REQUEST_SIZE), new Integer(this.baos.size()));
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
				m_log.trace("Got content-length: "+new Integer(this.contentLength));
			}
			return readTopASN1(this.contentLength-tlByteLength); // 'tlByteLength' bytes already read. 'this.contentLength <= MAX_REQUEST_SIZE' tested above.
		}
		// defined length, just read as many bytes as the length tag says
		if (m_log.isTraceEnabled()) {
			m_log.trace("Got ASN1 length: "+new Integer(length));
		}
		return readTopASN1(length);
	}
}
