def handler(request):
    print("noise on stdout {not json")  # must not corrupt the response
    body = request["body"].decode()
    return {"role": request["user"]["role"], "sub": request["user"].get("sub"), "echo": body}, 201
