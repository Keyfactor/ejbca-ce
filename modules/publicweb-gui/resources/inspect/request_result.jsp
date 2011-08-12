 <%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
 <%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
 
 <%@ include file="header.jsp" %>
<%@page import="org.apache.commons.fileupload.DiskFileUpload,org.apache.commons.fileupload.FileItem,java.util.List,java.util.Iterator,java.io.InputStream,org.cesecore.util.FileTools"%>

<jsp:useBean id="dump" class="org.ejbca.ui.web.pub.inspect.CertAndRequestDumpBean" scope="page" />
         
             <%
			DiskFileUpload upload = new DiskFileUpload();
			upload.setSizeMax(10000);
			upload.setSizeThreshold(9999);
			List items;
			items = upload.parseRequest(request);
			Iterator iter = items.iterator();
			while (iter.hasNext()) {
				FileItem item = (FileItem) iter.next();
				if (!item.isFormField()) {
					InputStream is = item.getInputStream();
					byte[] bytes = FileTools.readInputStreamtoBuffer(is);
					dump.setBytes(bytes);
				}
			}
             %>
            <h1 class="title"><c:out value="Certificate/CSR dump" /></h1>
            <hr/>
            <p>File is of type: <c:out value="${dump.type}"/></p>
<pre>
<c:out value="${dump.dump}"></c:out>    
</pre>            
 <%@ include file="footer.inc" %>
