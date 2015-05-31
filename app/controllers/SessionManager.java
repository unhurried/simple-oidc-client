package controllers;

import java.text.ParseException;

import play.mvc.Http;
import play.mvc.Http.Session;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.State;

public class SessionManager {

	// Cookie key
	private static final String ID_TOKEN = "id_token";
	private static final String USER_ID = "userId";
	private static final String STATE = "state";

    private static Session session() {
        return Http.Context.current().session();
    }

    private static void session(String key, String value) {
        session().put(key, value);
    }

    private static String session(String key) {
        return session().get(key);
    }

	/**
	 * Put the session into a login state as the user specified by userId.
	 * @param userId
	 */
	public static void login(String userId) {

		session(USER_ID, userId);
	}

	/**
	 * Put the session into a logout state.
	 */
	public static void logout() {

		session().remove(USER_ID);
	}

	/**
	 * Get the userId of the current login state.
	 * @return userId
	 */
	public static String getLoginUser() {

		String userIdAsString = session(USER_ID);
		if (userIdAsString == null || userIdAsString.equals("")) {
			return null;
		}
		return userIdAsString;
	}

	/**
	 * Get the state stored in the cookie. null is returned, if there is no state in the cookie.
	 * @return the state stored in the cookie.
	 */
	public static State getState() {

		String stateAsString = session(STATE);
		if (stateAsString == null || stateAsString.equals("")) {
			return null;
		}
		return new State(stateAsString);
	}

	/**
	 * Store a new state into a cookie.
	 * @param state to store in a cookie.
	 */
	public static void setState(State state) {

		session(STATE, state.getValue());
	}

	/**
	 * Get the ID Token stored in the cookie. null is returned, if there is no ID Token in the cookie.
	 * @return the ID Token stored in the cookie.
	 */
	public static JWT getIdToken() {

		String idTokenAsString = session(ID_TOKEN);
		if (idTokenAsString == null || idTokenAsString.equals("")) {
			return null;
		}

		try {
			return JWTParser.parse(idTokenAsString);
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Store a new ID Token into a cookie.
	 * @param ID Token to store in a cookie.
	 */
	public static void setIdToken(JWT idToken) {

		session(ID_TOKEN, idToken.serialize());
	}
}