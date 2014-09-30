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
package com.example.web;

import javax.ejb.EJB;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.example.ejb.MySimpleBeanLocal;
import com.example.entity.MyCounterData;

/**
 * This is a demo servlet that operates on a counter in a database table
 * @version $Id$
 */
public class Counter extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(Counter.class);
    
    private static final String UPDATE = "update";
    private static final String CLEAR  = "clear";

    @EJB
    private MySimpleBeanLocal mysimplebean;
   
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        StringBuffer out = new StringBuffer ("<html><body><h3>Counter Sample</h3>");
        String parm = request.getParameter (UPDATE);
        if (parm == null) {
        	parm = request.getParameter (CLEAR);
        	if (parm == null) {
        		MyCounterData ac =  mysimplebean.getCurrent();
        		out.append("Current counter status: ");
        		if (ac == null) {
        			out.append ("No hits so far...");
        		} else {
        			out.append(ac.getCounter ());
        		}
        	} else {
        	    mysimplebean.clearCounter ();
        		out.append("Counter was cleared");
        	}
        } else {
        	out.append("Counter's new value: ").append(mysimplebean.updateCounter());
        }
        out.append("<p><a href=\"" + request.getRequestURL ().toString () + "?" + UPDATE + "\">Update counter</a><br>" +
        		"<a href=\"" + request.getRequestURL ().toString () + "?" + CLEAR + "\">Clear counter</a></body></html>");
        response.getOutputStream ().print (out.toString ());
        log.info("Counting...");
    } // doGet

}
