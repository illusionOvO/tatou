from server.src.watermarking_method import WatermarkingMethod

class DummyPlugin(WatermarkingMethod):
    name = "dummy"

    def add_watermark(self, pdf, secret, key, position=None):
        return b"%PDF-1.4\n%%EOF"

    def read_secret(self, pdf, key):
        return "x"

    def is_watermark_applicable(self, pdf, position=None):
        return True

    def get_usage(self):
        return "dummy"
