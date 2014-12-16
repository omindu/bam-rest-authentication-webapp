package org.wso2.carbon.databridge.receiver.rest.authenticate;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.binary.Base64;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.databridge.commons.exception.AuthenticationException;
import org.wso2.carbon.databridge.core.DataBridgeReceiverService;

@Path("/")
public class Authenticate {

	@GET
	@Path("/getsessionid")
	@Produces(MediaType.TEXT_PLAIN)
	public Response getSessionID(@Context HttpServletRequest request) {

		String authHeader = request.getHeader("Authorization");
		String usernameAndPassword = new String(Base64.decodeBase64(authHeader.substring(6).getBytes()));

		String username = usernameAndPassword.split(":")[0];
		String password = usernameAndPassword.split(":")[1];

		DataBridgeReceiverService dataBridgeReceiverService = (DataBridgeReceiverService) PrivilegedCarbonContext
				.getThreadLocalCarbonContext().getOSGiService(DataBridgeReceiverService.class);

		try {

			String sessionID = dataBridgeReceiverService.login(username,password);
			String encoding = new String(Base64.encodeBase64(sessionID.getBytes()));
			
			return Response.status(Response.Status.OK).entity(encoding).build();

		} catch (AuthenticationException e) {
			return Response.status(Response.Status.FORBIDDEN).entity(e.getMessage()).build();
		} 
		

	}

}
