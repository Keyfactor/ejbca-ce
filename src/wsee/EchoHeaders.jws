/*
 * Copyright 2002,2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.axis.AxisFault;
import org.apache.axis.MessageContext;
import org.apache.axis.transport.http.HTTPConstants;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.Iterator;

/**
 * class to list headers sent in request as a string array
 */
public class EchoHeaders {

    /**
     * demo message context stuff
     * @return list of request headers
     */
    public String[] list() {
        HttpServletRequest request = getRequest();
        Enumeration headers=request.getHeaderNames();
        ArrayList list=new ArrayList();
        while (headers.hasMoreElements()) {
            String h = (String) headers.nextElement();
            String header=h+':'+request.getHeader(h);
            list.add(header);
        }
        String[] results=new String[list.size()];
        for(int i=0;i<list.size();i++) {
            results[i]=(String) list.get(i);
        }
        return results;
    }

    /**
     * get the caller; may involve reverse DNS
     * @return
     */
    public String whoami() {
        HttpServletRequest request = getRequest();
        String remote=request.getRemoteHost();
        return "Hello caller from "+remote;
    }

    /**
     * very simple method to echo the param.
     * @param param
     * @return
     */
    public String echo(String param) {
        return param;
    }
    
    /**
     * throw an axis fault with the text included
     */
    public void throwAxisFault(String param) throws AxisFault {
        throw new AxisFault(param);
    }
    
    public void throwException(String param) throws Exception { 
        throw new Exception(param);
    }

    /**
     * thow a runtime exception
     */
    public void throwRuntimeException(String param) { 
        throw new RuntimeException(param);
    }
    
    /**
     * helper
     * @return
     */
    private HttpServletRequest getRequest() {
        MessageContext context = MessageContext.getCurrentContext();
        HttpServletRequest req = (HttpServletRequest) context.getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST);
        return req;
    }

}