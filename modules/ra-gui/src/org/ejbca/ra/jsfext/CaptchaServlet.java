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
package org.ejbca.ra.jsfext;
 
import java.awt.Color;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nl.captcha.Captcha;
import nl.captcha.backgrounds.BackgroundProducer;
import nl.captcha.backgrounds.FlatColorBackgroundProducer;
import nl.captcha.backgrounds.GradiatedBackgroundProducer;
import nl.captcha.backgrounds.TransparentBackgroundProducer;
import nl.captcha.gimpy.DropShadowGimpyRenderer;
import nl.captcha.gimpy.RippleGimpyRenderer;
import nl.captcha.noise.CurvedLineNoiseProducer;
import nl.captcha.servlet.CaptchaServletUtil;

/**
 * Servlet responsible to create captcha image.
 * @version $Id$
 */
public class CaptchaServlet extends HttpServlet {
 
    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(CaptchaServlet.class);
    
    private Color getRandomColor(SecureRandom secureRandom){
        return new Color(secureRandom.nextInt(256), secureRandom.nextInt(256), secureRandom.nextInt(256));
    }
    
    private BackgroundProducer getRandomBackground(SecureRandom secureRandom){
        switch(secureRandom.nextInt(3)){
        case 0:
            return new FlatColorBackgroundProducer(getRandomColor(secureRandom));
        case 1:
            return new GradiatedBackgroundProducer(getRandomColor(secureRandom), getRandomColor(secureRandom));
        case 2:
            return new TransparentBackgroundProducer();
        default: 
            return new TransparentBackgroundProducer();
        }
    }
    
    @Override
    protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
 
        response.setHeader("Cache-Control", "no-cache");
        response.setDateHeader("Expires", 0);
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Max-Age", 0);

        SecureRandom secureRandom;
        try{
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        }catch(NoSuchAlgorithmException e){
            throw new IllegalStateException(e);
        }
        
        //Some captcha function. Free to be customized
        Captcha captcha = new Captcha.Builder(200, 50)
                .addText()
                .addBackground(getRandomBackground(secureRandom))
                .addNoise(new CurvedLineNoiseProducer(Color.black,  secureRandom.nextInt(3)+1))
                .gimp(new DropShadowGimpyRenderer(secureRandom.nextInt(3), secureRandom.nextInt(3)))
                .gimp(new RippleGimpyRenderer())
                .addBorder()
                .build();
        
        CaptchaServletUtil.writeImage(response, captcha.getImage());
        request.getSession().setAttribute(Captcha.NAME, captcha);
    }
 
    @Override
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        doPost(request, response);
    }
 
}