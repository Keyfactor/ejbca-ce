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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.apache.log4j.Logger;

/**
 * Encodes a TCP messages to a client.
 * 
 * @author lars
 * @version $Id$
 *
 */
public class TcpReturnMessage {
	private static final Logger log = Logger.getLogger(TcpReceivedMessage.class.getName());
	/**
	 * The message to be sent to be returned to the client.
	 */
	final public byte message[];
	/**
	 * true if the socket should be closed after returning the message to the client.
	 */
	final public boolean doClose;

	private TcpReturnMessage(byte m[], boolean c) {
		this.message = m;
		this.doClose = c;
	}
	/**
	 * @param resp message to be returned to the client.
	 * @param close true if the session to the client should be closed.
	 * @return the message to be sent to the client
	 * @throws IOException
	 */
	public static TcpReturnMessage createMessage(byte inMsg[], boolean close) throws IOException {
		final byte[] msg;
		final int msgType;
		final boolean doClose;
		if ( inMsg!=null && inMsg.length>0 ) {
			msg = inMsg;
			doClose = close;
			msgType = 5;
		} else {
			msg = new byte[1];
			msg[0] = 0;
			msgType = 3;
			doClose = true;
		}
		// 5 is pkiRep, 6 is errorMsgRep, 3 is finRep
		// errorMsgRep should only be used for TCP protocol errors, see 3.5.6 in cmp-transport-protocols
		//if (resp.getStatus() != ResponseStatus.SUCCESS) {
		//  msgType = 6;
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
			log.debug("Wrote length: '"+msg.length+3+"' Wrote version: '10' Wrote flags: '"+flags+"' Wrote msgType: '"+msgType+"' Wrote msg with length: "+msg.length);
		}
		return new TcpReturnMessage( bao.toByteArray(), doClose );
	}
}
