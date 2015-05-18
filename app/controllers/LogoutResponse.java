package controllers;

import com.nimbusds.oauth2.sdk.id.State;

import play.mvc.Http.Request;

/**
 * OpenID Connect Session Management 1.0 draft 23
 * 5.1.  Redirection to RP After Logout
 */
public class LogoutResponse {

	private static final String QUERY_STATE = "state";

	private State state;
	public State getState () {
		return this.state;
	}

	private LogoutResponse(String state) {

		if (state == null || state.equals("")) {
			this.state = null;
		} else {
			this.state = new State(state);
		}
	}

	public static LogoutResponse parse(Request request) {

		String state = request.getQueryString(QUERY_STATE);
		return new LogoutResponse(state);
	}

	public Boolean isStateValid(State stateInSession) {

		State stateInUri = this.state;
		if (stateInSession == null || stateInUri == null) {
			return false;
		}

		if (stateInUri.getValue().equals(stateInSession.getValue())) {
			return true;
		} else {
			return false;
		}
	}
}
