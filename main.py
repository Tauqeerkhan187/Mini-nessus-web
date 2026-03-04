# Author: TK
# Date: 05-03-2026
# Purpose: App entry point, creates flask app, starts server, binds HOST and PORT

import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    app.run(host=host, port=port, debug=True)

