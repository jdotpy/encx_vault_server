from flask import request, Response

import json

def json_response(content, code=200):
    return Response(json.dumps(content), status=code)
