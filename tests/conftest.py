"""
Giá trị CHỈ DÙNG CHO TEST: bộ Key demo cố định để test chạy được mà không cần file .env.
Được gán trước khi import `app`, nên load_dotenv() không ghi đè (giá trị trong .env thật không ảnh hưởng test).
Các prefix giữ nguyên như tài liệu (ak_live_1001full, ...); phần bí mật là chuỗi test, không dùng ở đâu khác.
"""
import os

_TEST_DEMO_KEYS = {
    "FULL_ACCESS": "ak_live_1001full_TESTONLYfullAccess000000000000000",
    "READ_ONLY": "ak_live_2002read_TESTONLYreadOnly0000000000000000",
    "IP_RESTRICTED": "ak_live_3003ipwl_TESTONLYipRestricted000000000000",
    "EXPIRED_KEY": "ak_live_4004expr_TESTONLYexpired00000000000000000",
    "REVOKED_KEY": "ak_live_5005revk_TESTONLYrevoked00000000000000000",
    "ROTATING_OLD_KEY": "ak_live_6006grce_TESTONLYgracePeriod0000000000000",
    "RATE_LIMITED_FREE": "ak_test_7007rate_TESTONLYrateLimited000000000000",
    "INTRUSION_TARGET": "ak_live_8008frez_TESTONLYintrusion000000000000000",
}

for _name, _raw in _TEST_DEMO_KEYS.items():
    os.environ[f"DEMO_KEY_{_name}"] = _raw
    os.environ[f"DEMO_SIGNING_SECRET_{_name}"] = f"whsec_TESTONLY_{_name.lower()}"
