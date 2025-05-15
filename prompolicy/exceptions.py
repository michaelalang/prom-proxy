class PermissionDenied(Exception):

    def __init__(self):
        super(PermissionDenied, self).__init__()
        self.msg = "Permission Denied, Authorization required"
        self.code = 403


class Learning(Exception):

    def __init__(self):
        super(Learning, self).__init__()
        self.msg = "Permission Denied, Auditing only"
        self.code = 200


class PromQLException(Exception):

    def __init__(self, msg):
        super(PromQLException, self).__init__()
        self.msg = msg
        self.code = 503


class CerbosGRPCDown(Exception):

    def __init__(self, msg):
        super(CerbosGRPCDown, self).__init__()
        self.msg = msg
        self.code = 503
