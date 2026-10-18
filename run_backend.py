"""Start the NetGuard FastAPI server (dev)."""

if __name__ == "__main__":
    import uvicorn
    from config import API_HOST, API_PORT

    uvicorn.run("app.main:app", host=API_HOST, port=API_PORT, reload=True)
