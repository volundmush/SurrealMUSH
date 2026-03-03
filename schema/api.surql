DEFINE FUNCTION OVERWRITE fn::api_level($req: object, $next: function, $level: int) -> object {
    IF !$auth.id {
        RETURN {
            error: "Unauthorized",
            status: 401
        };
    }

    IF !fn::admin_override($auth.id, $level) {
        RETURN {
            error: "Insufficient permissions",
            status: 403
        };
    }

    RETURN $req;
};

DEFINE API OVERWRITE "/users"
  FOR get
  THEN {
    LET $limit: int = math::min($request.query.limit ?? 25, 100);
    LET $offset: int = $request.query.offset ?? 0;
    RETURN {
      body: {
        data: SELECT * FROM user LIMIT $limit START $offset,
        total: SELECT COUNT(*) FROM user;
    }
  };

DEFINE API OVERWRITE "/users/:user_id/password"
    FOR post
    THEN {
        LET $user = <record<user>>$params.user_id;
        IF !$user {
            RETURN {
                error: "User not found",
                status: 404
            };
        }

        LET $password = $request.body.password;
        IF !$password {
            RETURN {
                error: "Password is required",
                status: 400
            };
        }

        LET $hashed_password = crypto::hash($password);
        UPDATE user SET password = $hashed_password WHERE id = $params.user_id;

        RETURN {
            body: {
                message: "Password updated successfully"
            }
        };
    }
