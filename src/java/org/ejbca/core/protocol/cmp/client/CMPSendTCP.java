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

package org.ejbca.core.protocol.cmp.client;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.apache.log4j.Logger;

/**
 * Client to send message to CMP server over TCP.
 * 
 * @version $Id$
 *
 */
public class CMPSendTCP {
	private static final Logger log = Logger.getLogger(CMPSendTCP.class.getName());
	public final int version;
	public final int msgType;
	public final int flags;
	public final byte response[];
	public final int headerLength;
	public final int bytesRead;

	public CMPSendTCP(final byte[] message, final Socket socket, final boolean doClose) throws IOException {
		final InputStream is = socket.getInputStream();
		final OutputStream os = new BufferedOutputStream(socket.getOutputStream());
		while( true ){
			final int nrOfOldBytes = is.available();
			if ( nrOfOldBytes<1 ) {
				break;
			}
			is.skip(nrOfOldBytes);
			log.debug(nrOfOldBytes +" junk bytes skipped.");
		}
		os.write(createTcpMessage(message));
		os.flush();

		final ByteArrayOutputStream headerBAOS = new ByteArrayOutputStream();
		final DataOutputStream headerDOS = new DataOutputStream(headerBAOS);
		final DataInputStream dis = new DataInputStream(is);
		// Read the length, 32 bits
		final int length = dis.readInt();
		headerDOS.writeInt(length);
		// System.out.println("Got a message claiming to be of length: " + len);
		// Read the version, 8 bits. Version should be 10 (protocol draft nr 5)
		this.version = dis.readByte();
		headerDOS.writeByte(this.version);

		// Read flags, 8 bits for version 10
		this.flags = dis.readByte();
		// patch flags if we want to force the client to close
		headerDOS.writeByte(doClose ? this.flags|1 : this.flags);
		// System.out.println("Got a message with flags (1 means close): " + flags);
		// Check if the client wants us to close the connection (LSB is 1 in that case according to spec)

		// Read message type, 8 bits
		this.msgType = dis.readByte();
		headerDOS.writeByte(this.msgType);

		headerDOS.close();
		final byte header[] = headerBAOS.toByteArray();
		this.headerLength = header.length;
		this.response = new byte[length+Integer.SIZE/8];
		System.arraycopy(header, 0, this.response, 0, header.length);
		// in java6 the two last rows could be written as this:
		// this.response = Arrays.copyOf(header, length+Integer.SIZE/8);
		int nrRead=this.headerLength;
		while( nrRead<this.response.length ) {
			final int nr = dis.read(this.response, nrRead, this.response.length-nrRead);
			if ( nr<0 ) {
				break;
			}
			nrRead += nr;
		}
		this.bytesRead = nrRead;
	}
    private static byte[] createTcpMessage(final byte[] msg) throws IOException {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bao); 
        // return msg length = msg.length + 3; 1 byte version, 1 byte flags and 1 byte message type
        dos.writeInt(msg.length+3);
        dos.writeByte(10);
        dos.writeByte(0); // 1 if we should close, 0 otherwise
        dos.writeByte(0); // 0 is pkiReq
        dos.write(msg);
        dos.flush();
        return bao.toByteArray();
    }
}
