import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    is_debug = os.getenv("FLASK_DEBUG", "0") == "1"
    port = int(os.getenv("PORT", "5000"))
    app.run(
        host="127.0.0.1",
        port=port,
        debug=is_debug,
    )
