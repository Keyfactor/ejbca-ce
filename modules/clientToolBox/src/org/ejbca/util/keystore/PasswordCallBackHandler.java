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
package org.ejbca.util.keystore;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/** Class for reading passwords from the console, as requested by the Sun PKCS#11 provider.
 * This class is created as a replacement for com.sun.security.auth.callback.TextCallbackHandler.
 * 1. That class is not available in other Java implementations
 * 2. That class echoes the password in JDK 5, we don't want that.
 * 
 * @version $Id$
 */
public class PasswordCallBackHandler implements CallbackHandler {
	public void handle(Callback[] callbacks)
	throws IOException, UnsupportedCallbackException {

		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof PasswordCallback) {
				// prompt the user for password, NOT echoing the password on either JDK5 or JDK6
				PasswordCallback pc = (PasswordCallback)callbacks[i];
				System.err.print(pc.getPrompt());
				System.err.flush();
				pc.setPassword(System.console().readPassword());

			} else {
				throw new UnsupportedCallbackException
				(callbacks[i], "Unrecognized Callback");
			}
		}
	}
}
