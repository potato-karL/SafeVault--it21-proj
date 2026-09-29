from app import create_app

app = create_app()

if __name__ == "__main__":
    # debug=True is fine for local dev only — never in production.
    app.run(debug=True)
