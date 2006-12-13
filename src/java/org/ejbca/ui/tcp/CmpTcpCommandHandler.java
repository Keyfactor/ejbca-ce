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
/*
 * This file is part of the QuickServer library 
 * Copyright (C) 2003-2005 QuickServer.org
 *
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the GNU Lesser General Public License. 
 * You should have received a copy of the GNU LGP License along with this 
 * library; if not, you can download a copy from <http://www.quickserver.org/>.
 *
 * For questions, suggestions, bug-reports, enhancement-requests etc.
 * visit http://www.quickserver.org
 *
 */

package org.ejbca.ui.tcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.security.cert.CertificateEncodingException;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcher;
import org.ejbca.util.Base64;
import org.quickserver.net.server.ClientBinaryHandler;
import org.quickserver.net.server.ClientEventHandler;
import org.quickserver.net.server.ClientHandler;
import org.quickserver.net.server.DataMode;
import org.quickserver.net.server.DataType;


public class CmpTcpCommandHandler implements ClientEventHandler, ClientBinaryHandler  {
	private static final Logger log = Logger.getLogger(CmpTcpCommandHandler.class.getName());
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
	
	public void gotConnected(ClientHandler handler)
	throws SocketTimeoutException, IOException {
		log.debug("CMP connection opened: "+handler.getHostAddress());
		handler.setDataMode(DataMode.BINARY, DataType.IN);
		handler.setDataMode(DataMode.BINARY, DataType.OUT);
	}
	
	public void lostConnection(ClientHandler handler) 
	throws IOException {
		log.debug("Connection lost: "+handler.getHostAddress());
	}
	public void closingConnection(ClientHandler handler) 
	throws IOException {
		log.debug("Connection closed: "+handler.getHostAddress());
	}
	
	
	public void handleBinary(ClientHandler handler, byte command[])
	throws SocketTimeoutException, IOException {
		if ((command == null) || (command.length == 0)) {
			handler.closeConnection(); // this is something fishy
			return;
		}
		String iMsg = intres.getLocalizedMessage("cmp.receivedmsg", handler.getHostAddress());
		log.info(iMsg);
		if (log.isDebugEnabled()) {
			log.debug("Got data of length "+command.length+": "+new String(Base64.encode(command)));			
		}

		IResponseMessage resp = null;
		boolean close = false;
		if (command.length > 7) {
			ByteArrayInputStream bai = new ByteArrayInputStream(command);
			DataInputStream dis = new DataInputStream(bai);
			// Read the length, 32 bits
			int len = dis.readInt();
			log.debug("Got a message claiming to be of length: " + len);
			
			// Read the version, 8 bits. Version should be 10 (protocol draft nr 5)
			int ver = dis.readByte();
			log.debug("Got a message with version: " + ver);
			
			// Read flags, 8 bits for version 10
			byte flags = dis.readByte();
			log.debug("Got a message with flags (1 means close): " + flags);
			// Check if the client wants us to close the connection (LSB is 1 in that case according to spec)
			if ((flags & 0xFE) == 1) {
				close = true;
			}
			
			// Read message type, 8 bits
			int msgType = dis.readByte();
			log.debug("Got a message of type: " +msgType);
			
			// Read message
			int msgLen = command.length - 4;
			// They should match
			if (len == msgLen) {
				if (msgLen < 5000) {
					byte[] msg = new byte[len]; 					
					for (int i = 7; i < command.length; i++) {
						msg[i-7] = command[i];
					}
					// We got our message now, we can actually process it I think
					if (log.isDebugEnabled()) {
						log.debug("Received a CMP message by TCP: "+new String(Base64.encode(msg)));
					}
					// We must use an administrator with rights to create users
					Admin administrator = new Admin(Admin.TYPE_RACOMMANDLINE_USER, handler.getHostAddress());

					CmpMessageDispatcher dispatcher = new CmpMessageDispatcher(administrator, CmpTcpConfiguration.instance().getProperties());
					resp = dispatcher.dispatch(msg);
					if (resp == null) {
						// unknown error?
						String errMsg = intres.getLocalizedMessage("cmp.errornullresp");
						log.error(errMsg);
					} else {
						log.debug("Sending back CMP response to client.");
					}

				} else {
					String errMsg = intres.getLocalizedMessage("cmp.errortcptoolongmsg", Integer.valueOf(msgLen));
					log.error(errMsg);	
					handler.closeConnection(); // This is something malicious
				}
			} else {
				String errMsg = intres.getLocalizedMessage("cmp.errortcpwronglen", Integer.valueOf(msgLen), Integer.valueOf(len));
				log.error(errMsg);
				handler.closeConnection(); // This is something malicious
			}
		}
		// Send back reply
		byte[] sendBack = null;
		if (resp != null) {
			sendBack = createReturnTcpMessage(resp, close);			
		} else {
			log.debug("Not sending back anything.");
		}
		if (sendBack != null) {
			log.debug("Sending "+sendBack.length+" bytes to client");
			handler.sendClientBinary(sendBack);			
			iMsg = intres.getLocalizedMessage("cmp.sentresponsemsg", handler.getHostAddress());
			log.info(iMsg);
		} else {
			close = true;
		}
		if (close) {
			handler.closeConnection(); // It's time to say good bye			
		}
	}
	
	private static byte[] createReturnTcpMessage(IResponseMessage resp, boolean close) throws IOException {
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		byte[] msg;
		try {
			msg = resp.getResponseMessage();
		} catch (CertificateEncodingException e) {
			msg = null;
		} 
		boolean doClose = close;
		// 5 is pkiRep, 6 is errorMsgRep, 3 is finRep
		// errorMsgRep should only be used for TCP protocol errors, see 3.5.6 in cmp-transport-protocols
		int msgType = 5;
		//if (resp.getStatus() != ResponseStatus.SUCCESS) {
		//	msgType = 6;
		//}
		if ( (msg == null) || (msg.length == 0) ) {
			msg = new byte[1];
			msg[0] = 0;
			msgType = 3;
			doClose = true;
		}
		int len = msg.length;
		DataOutputStream dos = new DataOutputStream(bao); 
		// return msg length = msg.length + 3; 1 byte version, 1 byte flags and 1 byte message type
		dos.writeInt(len+3);
		dos.writeByte(10);
		int flags = (doClose == true ? 1 : 0); // 1 if we should close, 0 otherwise
		dos.writeByte(flags); 
		dos.writeByte(msgType); 
		dos.write(msg);
		dos.flush();
		if (log.isDebugEnabled()) {
			log.debug("Wrote length: "+len+3);
			log.debug("Wrote version: 10");
			log.debug("Wrote flags: "+flags);
			log.debug("Wrote msgType: "+msgType);
			log.debug("Wrote msg with length: "+msg.length);
		}
		return bao.toByteArray();
	}
	    
}