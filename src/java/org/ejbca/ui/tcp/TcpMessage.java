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

package org.ejbca.ui.tcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERObject;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.ejbca.util.Base64;

/**
 * Encodes and decodes TCP messages to and from a client.
 * @author lars
 *
 */
public class TcpMessage {
	private static final Logger log = Logger.getLogger(TcpMessage.class.getName());
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();
	private final boolean close;
	private final DERObject message;

	private TcpMessage() { // this notifies an error
		this.close = true;
		this.message = null;
	}
	private TcpMessage( boolean close, DERObject message) { // message OK
		this.close = close;
		this.message = message;
	}
	/**
	 * @return true if the session should be closed after returning to the client
	 */
	public boolean isClose() {
		return this.close;
	}
	/**
	 * @return the message from the client decoded from ASN1
	 */
	public DERObject getMessage() {
		return this.message;
	}
	/**
	 * @param command bytes from client. The payload of has to be ASN1 encoded
	 * @return the message ASN1 decoded
	 * @throws IOException
	 */
	static public TcpMessage getTcpMessage(byte command[]) throws IOException {
		if ( command==null || command.length==0 ) {
			return new TcpMessage(); // this is something fishy
		}
		if (log.isTraceEnabled()) {
			log.trace("Got data of length "+command.length+": "+new String(Base64.encode(command)));			
		}
		final int cmpMessageStartOffset = 7;
		if (command.length <= cmpMessageStartOffset) {
			return new TcpMessage();
		}
		final ByteArrayInputStream bai = new ByteArrayInputStream(command);
		final DataInputStream dis = new DataInputStream(bai);
		// Read the length, 32 bits
		final int len = dis.readInt(); // 4 bytes
		log.debug("Got a message claiming to be of length: " + len);

		// Read the version, 8 bits. Version should be 10 (protocol draft nr 5)
		final int ver = dis.readByte(); // 1 byte
		log.debug("Got a message with version: " + ver);

		// Read flags, 8 bits for version 10
		final byte flags = dis.readByte(); // 1 byte
		log.debug("Got a message with flags (1 means close): " + flags);
		// 'flags' will be used to check if the client wants us to close the connection (LSB is 1 in that case according to spec)

		// Read message type, 8 bits
		final int msgType = dis.readByte(); // 1 byte
		// now 'payLoadStrartOffset' bytes has been read
		log.debug("Got a message of type: " +msgType);

		// Read message
		final int msgLen = command.length - 4;
		// They should match
		if ( len!=msgLen ) {
			log.error( intres.getLocalizedMessage("cmp.errortcpwronglen", new Integer(msgLen), new Integer(len)) );
			return new TcpMessage();// This is something malicious
		}
		if ( msgLen>=5000 ) {
			log.error( intres.getLocalizedMessage("cmp.errortcptoolongmsg", new Integer(msgLen)) );
			return new TcpMessage();// This is something malicious
		}
		// The CMP message is the rest of the stream that has not been read yet.
		try {
			return new TcpMessage( (flags&0xFE)==1, new LimitLengthASN1Reader(dis, command.length-cmpMessageStartOffset).readObject() );
		} catch( Throwable e ) {
			log.error( intres.getLocalizedMessage("cmp.errornoasn1"), e );
			return new TcpMessage();
		}
	}
	/**
	 * @param resp message to be returned to the client.
	 * @param close true if the session to the client should be closed.
	 * @return the bytes to be sent to the client
	 * @throws IOException
	 */
	public static byte[] createReturnTcpMessage(IResponseMessage resp, boolean close) throws IOException {
		final byte[] msg;
		final int msgType;
		final boolean doClose;
		{
			byte tmp[];
			try {
				tmp = resp.getResponseMessage();
			} catch (CertificateEncodingException e) {
				tmp = null;
			}
			if ( tmp!=null && tmp.length>0 ) {
				msg = tmp;
				doClose = close;
				msgType = 5;
			} else {
				msg = new byte[1];
				msg[0] = 0;
				msgType = 3;
				doClose = true;
			}
		}
		// 5 is pkiRep, 6 is errorMsgRep, 3 is finRep
		// errorMsgRep should only be used for TCP protocol errors, see 3.5.6 in cmp-transport-protocols
		//if (resp.getStatus() != ResponseStatus.SUCCESS) {
		//	msgType = 6;
		//}
		final ByteArrayOutputStream bao = new ByteArrayOutputStream();
		final DataOutputStream dos = new DataOutputStream(bao); 
		// return msg length = msg.length + 3; 1 byte version, 1 byte flags and 1 byte message type
		dos.writeInt(msg.length+3);
		dos.writeByte(10);
		final int flags = doClose ? 1 : 0; // 1 if we should close, 0 otherwise
		dos.writeByte(flags); 
		dos.writeByte(msgType); 
		dos.write(msg);
		dos.flush();
		if (log.isDebugEnabled()) {
			log.debug("Wrote length: "+msg.length+3);
			log.debug("Wrote version: 10");
			log.debug("Wrote flags: "+flags);
			log.debug("Wrote msgType: "+msgType);
			log.debug("Wrote msg with length: "+msg.length);
		}
		return bao.toByteArray();
	}
}
