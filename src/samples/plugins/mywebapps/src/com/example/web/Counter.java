package com.example.web;

import javax.ejb.EJB;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.example.ejb.MySimpleBeanLocal;
import com.example.entity.MyCounterData;

public class Counter extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(Counter.class);
    
    private static final String UPDATE = "update";
    private static final String CLEAR  = "clear";

    @EJB
    private MySimpleBeanLocal mysimplebean;
   
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }


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
