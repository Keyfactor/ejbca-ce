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
 
package org.ejbca.ui.web.pub;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ejbca.ui.web.RequestHelper;


/**
 * Prints debug info back to browser client
 * @version $Id$
 */
public class ServletDebug {
    private final ByteArrayOutputStream buffer;
    private final PrintStream printer;
    private final HttpServletRequest request;
    private final HttpServletResponse response;

    public ServletDebug(HttpServletRequest request, HttpServletResponse response) {
        buffer = new ByteArrayOutputStream();
        printer = new PrintStream(buffer);
        this.request = request;
        this.response = response;
    }

    public void printDebugInfo() throws IOException, ServletException {
    	String errorform = request.getParameter ("errorform");
    	String errormessage = new String(buffer.toByteArray());
    	if (errorform == null){
            request.setAttribute("ErrorMessage", errormessage);
            request.getRequestDispatcher("error.jsp").forward(request, response);
    	}
    	else{
    		int i = errorform.indexOf("@ERROR@");
    		if (i > 0){
    			errorform = errorform.substring (0, i) + errormessage + errorform.substring(i + 7);
    		}
    		response.setContentType("text/html");
    		response.getOutputStream().print(errorform);
    	}
    }

    public void print(Object o) {
        printer.println(o);
    }

    public void printMessage(String msg) {
        print(msg);
    }

    public void printInsertLineBreaks(byte[] bA) {
        BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(bA)));
        while (true) {
            String line;
            try {
                line = br.readLine();
            } catch (IOException e) {
                throw new IllegalStateException("Unexpected IOException was caught.", e);
            }
            if (line == null) {
                break;
            }
            print(line.toString());
        }
    }

    public void takeCareOfException(Throwable t) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        t.printStackTrace(new PrintStream(baos));
        print("Exception:");

        try {
            printInsertLineBreaks(baos.toByteArray());
        } catch (Exception e) {
            e.printStackTrace(printer);
        }

        request.setAttribute("Exception", "true");
    }

    public void ieCertFix(byte[] bA) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream tmpPrinter = new PrintStream(baos);
        RequestHelper.ieCertFormat(bA, tmpPrinter);
        printInsertLineBreaks(baos.toByteArray());
    }
}
 // Debug
