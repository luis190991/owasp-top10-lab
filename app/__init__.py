from flask import Flask, render_template
from .database import init_db


def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.secret_key = 'dev-secret-key-not-for-production'

    from .labs.a01_access_control import a01
    from .labs.a02_misconfiguration import a02
    from .labs.a03_supply_chain import a03
    from .labs.a04_crypto import a04
    from .labs.a05_injection import a05
    from .labs.a06_insecure_design import a06
    from .labs.a07_auth_failures import a07
    from .labs.a08_integrity import a08
    from .labs.a09_logging import a09
    from .labs.a10_exceptions import a10

    app.register_blueprint(a01, url_prefix='/a01')
    app.register_blueprint(a02, url_prefix='/a02')
    app.register_blueprint(a03, url_prefix='/a03')
    app.register_blueprint(a04, url_prefix='/a04')
    app.register_blueprint(a05, url_prefix='/a05')
    app.register_blueprint(a06, url_prefix='/a06')
    app.register_blueprint(a07, url_prefix='/a07')
    app.register_blueprint(a08, url_prefix='/a08')
    app.register_blueprint(a09, url_prefix='/a09')
    app.register_blueprint(a10, url_prefix='/a10')

    from .labs.solutions import solutions
    app.register_blueprint(solutions, url_prefix='/solutions')

    @app.route('/')
    def index():
        return render_template('index.html')

    return app
