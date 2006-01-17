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
 
package org.ejbca.ui.web.pub;

import java.io.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Prints debug info back to browser client
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
        request.setAttribute("ErrorMessage", new String(buffer.toByteArray()));
        request.getRequestDispatcher("error.jsp").forward(request, response);
    }

    public void print(Object o) {
        printer.println(o);
    }

    public void printMessage(String msg) {
        print("<p>" + msg);
    }

    public void printInsertLineBreaks(byte[] bA) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(bA)));

        while (true) {
            String line = br.readLine();

            if (line == null) {
                break;
            }

            print(line.toString() + "<br>");
        }
    }

    public void takeCareOfException(Throwable t) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        t.printStackTrace(new PrintStream(baos));
        print("<h4>Exception:</h4>");

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
