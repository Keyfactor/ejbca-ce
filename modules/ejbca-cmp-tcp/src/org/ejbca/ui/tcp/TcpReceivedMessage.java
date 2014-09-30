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

package org.ejbca.ui.tcp;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

import org.apache.log4j.Logger;
import org.cesecore.util.Base64;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Decodes a TCP messages from a client.
 * 
 * @author lars
 * @version $Id$
 *
 */
public class TcpReceivedMessage {
	private static final Logger log = Logger.getLogger(TcpReceivedMessage.class.getName());
	/** Internal localization of logs and errors */
	private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
	/**
	 * true if the session should be closed after returning to the client
	 */
	public final boolean doClose;
	/**
	 * the message from the client decoded from ASN1
	 */
	public final byte[] message;

	private TcpReceivedMessage() { // this notifies an error
		this.doClose = true;
		this.message = null;
	}

	private TcpReceivedMessage( boolean close, byte[] message) { // message OK
		this.doClose = close;
		this.message = message;
	}
	/**
	 * @param command bytes from client. The payload of has to be ASN1 encoded
	 * @return the message ASN1 decoded
	 * @throws IOException
	 */
	static public TcpReceivedMessage getTcpMessage(byte command[]) throws IOException {
		if ( command==null || command.length==0 ) {
			return new TcpReceivedMessage(); // this is something fishy
		}
		if (log.isTraceEnabled()) {
			log.trace("Got data of length "+command.length+": "+new String(Base64.encode(command)));			
		}
		final int cmpMessageStartOffset = 7;
		if (command.length <= cmpMessageStartOffset) {
			return new TcpReceivedMessage();
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
			log.error( intres.getLocalizedMessage("cmp.errortcpwronglen", Integer.valueOf(msgLen), Integer.valueOf(len)) );
			return new TcpReceivedMessage();// This is something malicious
		}
		if ( msgLen>=5000 ) {
			log.error( intres.getLocalizedMessage("cmp.errortcptoolongmsg", Integer.valueOf(msgLen)) );
			return new TcpReceivedMessage();// This is something malicious
		}
		// The CMP message is the rest of the stream that has not been read yet.
		try {
			byte[] ba = new byte[command.length-cmpMessageStartOffset];
			dis.read(ba);
			return new TcpReceivedMessage( (flags&0x01)>0, ba);
		} catch( Throwable e ) { // NOPMD: any error return empty
			log.error( intres.getLocalizedMessage("cmp.errornoasn1"), e );
			return new TcpReceivedMessage();
		}
	}
}
