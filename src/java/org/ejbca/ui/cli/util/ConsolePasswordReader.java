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
package org.ejbca.ui.cli.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;

/** Class for reading passwords from the console, it has three different ways to try:
 * 1. Java6 console password reading
 * 2. JLine console library password reading
 * 3 Clear text (System.in)
 * Usage:
 * <pre>
 * System.out.print("Enter password: ");
 * ConsolePasswordReader r = new ConsolePasswordReader();
 * String password = String.valueOf(r.readPassword());            	
 * </pre>
 * 
 * @version $Id$
 */
public class ConsolePasswordReader implements PasswordReader {
	public char[] readPassword() throws IOException {
		// We want to use the new Console class in java6, but we still want to be able to
		// compile under java5
		// Using reflection to be able to build this java 6 code under java 5 
		char[] passwd = null;
		try {
			try {
				// For some reason System.console does not work when running from within ant
				// JLine however does work.
				Class implClass = Class.forName("java.lang.System");
    			Method m = implClass.getMethod("console", (Class[])null);
    			Object cons = m.invoke(this, (Object[])null);
    			if (cons != null) {
    				Method m1 = cons.getClass().getMethod("readPassword", (Class[])null);
    				passwd = (char[])m1.invoke(cons, (Object[])null);
    			} else {
    				throw new IOException("No java6 console detected.");        				
    			}    				
			} catch (Exception e) {
				// If we can't find the console method on System, i.e. we are running java5
				// we will try to use the jline console library
    			passwd = new jline.ConsoleReader().readLine(new Character((char)0)).toCharArray();
			}
		} catch (Exception e) {
			// If everything else fails, fallback to clear text input
			passwd =  new BufferedReader(new InputStreamReader(System.in)).readLine().toCharArray();
		}
		return passwd;
	}
}
