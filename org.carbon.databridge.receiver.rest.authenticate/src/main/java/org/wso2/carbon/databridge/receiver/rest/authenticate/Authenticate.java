/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 * 
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.databridge.receiver.rest.authenticate;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.binary.Base64;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.databridge.commons.exception.AuthenticationException;
import org.wso2.carbon.databridge.core.DataBridgeReceiverService;
import org.wso2.carbon.databridge.receiver.rest.authenticate.utils.Constants;

@Path("/")
public class Authenticate {

	@GET
	@Path("/getsessionid")
	@Produces(MediaType.TEXT_PLAIN)
	public Response getSessionID(@Context HttpServletRequest request) {

		String authHeader = request.getHeader("Authorization");

		// The client sends the username & password using basic access
		// authentication via the http header.
		// Authorization header is in the form of 'Basic XXXXXXXX'
		// To decode the the credentials, the realm is separated
		String usernameAndPassword = new String(Base64.decodeBase64(authHeader.substring(Constants
		                                        .BASIC_AUTHENTICATION_REALM_SEPARATOR_INDEX).getBytes()));

		String[] credentials = usernameAndPassword.split(Constants.USERNAME_PASSWORD_SEPERATOR);

		String username = credentials[0];
		String password = credentials[1];

		DataBridgeReceiverService dataBridgeReceiverService = (DataBridgeReceiverService) PrivilegedCarbonContext
		                                                      .getThreadLocalCarbonContext()
		                                                      .getOSGiService(DataBridgeReceiverService.class);

		try {

			String sessionID = dataBridgeReceiverService.login(username, password);
			String encoding = new String(Base64.encodeBase64(sessionID.getBytes()));

			return Response.status(Response.Status.OK).entity(encoding).build();

		} catch (AuthenticationException e) {
			return Response.status(Response.Status.FORBIDDEN).entity(e.getMessage()).build();
		}

	}

}
