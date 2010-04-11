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

import java.io.IOException;
import java.net.SocketTimeoutException;

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

/**
 * Class receiving TCP messages from QuickServer (receives quickserver events) and routing them to the correct CMP handler class.
 * 
 * @author tomas
 * @version $Id$
 */
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
		log.info(intres.getLocalizedMessage("cmp.receivedmsg", handler.getHostAddress()));
		final TcpMessage cmpTcpMessage = TcpMessage.getTcpMessage(command);
		if ( cmpTcpMessage.getMessage()==null )  {
			log.error( intres.getLocalizedMessage("cmp.errornoasn1") );
			handler.closeConnection();
			return;
		}
		// We must use an administrator with rights to create users
		final Admin administrator = new Admin(Admin.TYPE_RA_USER, handler.getHostAddress());
		final CmpMessageDispatcher dispatcher = new CmpMessageDispatcher(administrator);
		final IResponseMessage resp = dispatcher.dispatch(cmpTcpMessage.getMessage());
		if ( resp==null) {
			// unknown error?
			handler.closeConnection();
			return;
		}
		log.debug("Sending back CMP response to client.");
		// Send back reply
		final byte[] sendBack = TcpMessage.createReturnTcpMessage(resp, cmpTcpMessage.isClose());
		if ( sendBack==null ) {
			handler.closeConnection();
			return;
		}
		log.debug("Sending "+sendBack.length+" bytes to client");
		handler.sendClientBinary(sendBack);			
		final String iMsg = intres.getLocalizedMessage("cmp.sentresponsemsg", handler.getHostAddress());
		log.info(iMsg);
		if (cmpTcpMessage.isClose()) {
			handler.closeConnection(); // It's time to say good bye			
		}
	}
}