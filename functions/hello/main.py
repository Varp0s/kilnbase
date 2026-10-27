def handler(request):
    """GET /functions/v1/hello?name=Ada with the anon key (and optionally a user's token)."""
    user = request["user"]
    name = request["query"].get("name", "world")
    return {"message": f"Hello, {name}!", "role": user["role"], "user_id": user.get("sub")}
