from ..exceptions import PromFilterException


class PromFilter(object):
    def filter(self, content):
        raise PromFilterException("Not Implemented")

    def paged_filter(self, content, page_size):
        raise PromFilterException("Not Implemented")

    def is_healthy(self):
        raise PromFilterException("Not Implemented")
