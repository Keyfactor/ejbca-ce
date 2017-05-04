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

import java.io.IOException;
import java.net.SocketTimeoutException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;
import org.quickserver.net.server.ClientBinaryHandler;
import org.quickserver.net.server.ClientEventHandler;
import org.quickserver.net.server.ClientHandler;
import org.quickserver.net.server.DataMode;
import org.quickserver.net.server.DataType;

/**
 * Class receiving TCP messages from QuickServer (receives quickserver events) and routing them to the correct CMP handler class.
 * 
 * @version $Id$
 */
public class CmpTcpCommandHandler implements ClientEventHandler, ClientBinaryHandler  {

	private static final Logger LOG = Logger.getLogger(CmpTcpCommandHandler.class.getName());
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();
    private static EjbLocalHelper ejb = null;
	
	private static synchronized EjbLocalHelper getEjb() {
		if (ejb == null) {
			ejb = new EjbLocalHelper();
		}
		return ejb;
	}
	
    @Override
	public void gotConnected(final ClientHandler handler) throws SocketTimeoutException, IOException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("CMP connection opened: "+handler.getHostAddress());
		}
		handler.setDataMode(DataMode.BINARY, DataType.IN);
		handler.setDataMode(DataMode.BINARY, DataType.OUT);
	}

    @Override
	public void lostConnection(final ClientHandler handler) throws IOException {
		LOG.debug("Connection lost: "+handler.getHostAddress());
	}

    @Override
	public void closingConnection(final ClientHandler handler) throws IOException {
		LOG.debug("Connection closed: "+handler.getHostAddress());
	}

    @Override
	public void handleBinary(final ClientHandler handler, final byte command[])	throws SocketTimeoutException, IOException {
		LOG.info(INTRES.getLocalizedMessage("cmp.receivedmsg", handler.getHostAddress()));
		long startTime = System.currentTimeMillis();
		final TcpReceivedMessage cmpTcpMessage = TcpReceivedMessage.getTcpMessage(command);
		if (cmpTcpMessage.message == null) {
			handler.closeConnection();
		} else {
		    final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(new WebPrincipal("CmpTcp", handler.getHostAddress()));
		    byte[] result = null;
			try {
			    result = getEjb().getRaMasterApiProxyBean().cmpDispatch(authenticationToken, cmpTcpMessage.message, "tcp");
			} catch (NoSuchAliasException e) {
                LOG.error(e.getMessage(), e);
                handler.closeConnection();
                return;
            }
			if (LOG.isDebugEnabled()) {
				LOG.debug("Sending back CMP response to client.");
			}
			// Send back reply
			final TcpReturnMessage sendBack = TcpReturnMessage.createMessage(result, cmpTcpMessage.doClose);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Sending "+sendBack.message.length+" bytes to client");
			}
			handler.sendClientBinary(sendBack.message);
			long endTime = System.currentTimeMillis();
			final String iMsg = INTRES.getLocalizedMessage("cmp.sentresponsemsg", handler.getHostAddress(), Long.valueOf(endTime - startTime));
			LOG.info(iMsg);
			if ( cmpTcpMessage.doClose || sendBack.doClose ) {
				handler.closeConnection(); // It's time to say good bye			
			}
		}
	}
}
