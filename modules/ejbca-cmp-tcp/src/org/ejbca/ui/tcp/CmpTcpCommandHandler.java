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
import java.security.cert.CertificateEncodingException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.request.ResponseMessage;
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
	
	public void gotConnected(final ClientHandler handler) throws SocketTimeoutException, IOException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("CMP connection opened: "+handler.getHostAddress());
		}
		handler.setDataMode(DataMode.BINARY, DataType.IN);
		handler.setDataMode(DataMode.BINARY, DataType.OUT);
	}

	public void lostConnection(final ClientHandler handler) throws IOException {
		LOG.debug("Connection lost: "+handler.getHostAddress());
	}

	public void closingConnection(final ClientHandler handler) throws IOException {
		LOG.debug("Connection closed: "+handler.getHostAddress());
	}

	public void handleBinary(final ClientHandler handler, final byte command[])	throws SocketTimeoutException, IOException {
		LOG.info(INTRES.getLocalizedMessage("cmp.receivedmsg", handler.getHostAddress()));
		long startTime = System.currentTimeMillis();
		final TcpReceivedMessage cmpTcpMessage = TcpReceivedMessage.getTcpMessage(command);
		if ( cmpTcpMessage.message==null )  {
			handler.closeConnection();
		} else {
			// We must use an administrator with rights to create users
			final AuthenticationToken administrator = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CmpTcp: "+handler.getHostAddress()));
			final ResponseMessage resp;
			try {
				 resp = getEjb().getCmpMessageDispatcherSession().dispatch(administrator, cmpTcpMessage.message, "tcp");
			} catch (IOException e) {
				LOG.error( INTRES.getLocalizedMessage("cmp.errornoasn1"), e );
				handler.closeConnection();
				return;
			} catch (NoSuchAliasException e) {
                LOG.error(e.getMessage(), e );
                handler.closeConnection();
                return;
            }
			if (LOG.isDebugEnabled()) {
				LOG.debug("Sending back CMP response to client.");
			}
			// Send back reply
			final TcpReturnMessage sendBack;
			{
				byte tmp[] = null;
				try {
					if (resp!=null) {
						tmp = resp.getResponseMessage();
					}
				} catch (CertificateEncodingException e) {
					LOG.debug("CertificateEncodingException: " + e.getMessage());
				}
				sendBack = TcpReturnMessage.createMessage(tmp, cmpTcpMessage.doClose);
			}
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
