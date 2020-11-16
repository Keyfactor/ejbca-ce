<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>EJBCA MS Autoenrollment</title>
    </head>
    <body>
        <h1>EJBCA MS Autoenrollment Proxy v1.0.1</h1>
        <p>This Autoenrollment service proxies autoenrollment requests to EJBCA for Active Directory Domain Users and Computers
        to seamlessly auto enroll for certificates issued by EJBCA. 
        <br/><br/>Read the documentation how to configure this service in your Active Directory Domain.
        </p>
        <form action="MSEnrollmentServlet" method="POST">
            <input type="submit" value="Debug info">
        </form>
    </body>
</html>
