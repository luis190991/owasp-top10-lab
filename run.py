import argparse
from app import create_app
from app.database import init_db

parser = argparse.ArgumentParser()
parser.add_argument('--init-db', action='store_true')
args, _ = parser.parse_known_args()

app = create_app()

if args.init_db:
    with app.app_context():
        init_db()
        print("[+] Database initialized with lab data.")

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
