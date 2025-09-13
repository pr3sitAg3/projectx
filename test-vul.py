# File: app.py

import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/list-files")
def list_files():
    """
    This endpoint is vulnerable to Command Injection.
    It takes a 'dir' parameter from the user and executes a shell command with it.
    """
    user_input = request.args.get('dir')

    if not user_input:
        return "Please provide a 'dir' parameter.", 400

    # VULNERABLE: User input is directly formatted into a shell command.
    command = f"ls -l {user_input}"
    
    # The use of `shell=True` with un-sanitized user input is extremely dangerous.
    result = subprocess.run(
        command, 
        shell=True, 
        capture_output=True, 
        text=True
    )

    return f"<pre>Command Output:\n{result.stdout}{result.stderr}</pre>"

if __name__ == "__main__":
    app.run(debug=True)
