class LoginPage:
    parent: None  # EasyAuthServer / EasyAuthClient

    @classmethod
    def mark(cls):
        def override(func):
            cls.parent.html_login_page = func
            return func

        return override


class RegisterPage:
    parent: None  # EasyAuthServer / EasyAuthClient

    @classmethod
    def mark(cls):
        def override(func):
            cls.parent.html_register_page = func
            return func

        return override


class ActivationPage:
    parent: None  # EasyAuthServer / EasyAuthClient

    @classmethod
    def mark(cls):
        def override(func):
            cls.parent.html_activation_page = func
            return func

        return override


class NotFoundPage:
    parent: None  # EasyAuthServer / EasyAuthClient

    @classmethod
    def mark(cls):
        def override(func):
            cls.parent.html_not_found_page = func
            return func

        return override


class ForbiddenPage:
    parent: None  # EasyAuthServer / EasyAuthClient

    @classmethod
    def mark(cls):
        def override(func):
            cls.parent.html_forbidden_page = func
            return func

        return override
