class Error(Exception):
    def __init__(self, code, message, exit_code=5, *, retryable=False, partial=None):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code
        self.retryable, self.partial = retryable, partial
