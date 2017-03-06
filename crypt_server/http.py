from flask import request, Response

import json

def json_response(content, code=200):
    return Response(json.dumps(content), status=code)

def binary_response(payload, code=200):
    return Response(
        payload,
        status=code,
        headers={'Content-Type': "application/octet-stream"},
    )
    
