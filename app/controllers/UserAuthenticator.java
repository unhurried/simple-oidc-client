package controllers;

import play.mvc.Result;
import play.mvc.Security;
import play.mvc.Http.Context;

public class UserAuthenticator extends Security.Authenticator {

	@Override
    public String getUsername(Context ctx) {
        return SessionManager.getLoginUser();
    }

	@Override
    public Result onUnauthorized(Context ctx) {
        return redirect(routes.LoginController.getPage());
    }
}
