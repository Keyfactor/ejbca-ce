 <%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
 <%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
 
 <%@ include file="header.jsp" %>
<%@page import="org.apache.commons.fileupload.servlet.ServletFileUpload,org.apache.commons.fileupload.FileItem,java.util.List,java.util.Iterator,java.io.InputStream,org.cesecore.util.FileTools,
org.apache.commons.fileupload.disk.DiskFileItemFactory"%>

<jsp:useBean id="dump" class="org.ejbca.ui.web.pub.inspect.CertAndRequestDumpBean" scope="page" />
         
             <%
            // Check that we have a file upload request
            boolean isMultipart = ServletFileUpload.isMultipartContent(request);
            if (isMultipart) {
              final DiskFileItemFactory diskFileItemFactory = new DiskFileItemFactory();
              diskFileItemFactory.setSizeThreshold(9999);
              ServletFileUpload upload = new ServletFileUpload(diskFileItemFactory);
			  upload.setSizeMax(10000);
			  List<FileItem> items = upload.parseRequest(request);
			  for(FileItem item : items) {
				if (!item.isFormField()) {
					InputStream is = item.getInputStream();
					byte[] bytes = FileTools.readInputStreamtoBuffer(is);
					dump.setBytes(bytes);
				}
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
