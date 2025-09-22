# This is basic example of creating custom caching function
# KSMCache only stores last request, however you can use any tool to this extend functionality

from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.core import KSMCache, KSMHttpResponse
from http import HTTPStatus


def caching_post_function(
        url, transmission_key, encrypted_payload_and_signature, verify_ssl_certs=True, proxy_url=None
):
    ksm_rs = SecretsManager.post_function(
        url, transmission_key, encrypted_payload_and_signature, verify_ssl_certs
    )

    if ksm_rs.status_code < 400:
        KSMCache.save_cache(transmission_key.key + ksm_rs.data)
        return ksm_rs

    # KSMCache can be empty
    cached_data = KSMCache.get_cached_data()
    cached_transmission_key = cached_data[:32]
    transmission_key.key = cached_transmission_key
    data = cached_data[32 : len(cached_data)]

    print(f"Using cached data")

    new_rs = KSMHttpResponse(HTTPStatus.OK, data, None)
    return new_rs



secrets_manager = SecretsManager(
    config=FileKeyValueStorage('ksm-config.json'),
    verify_ssl_certs=False,
    custom_post_function=caching_post_function
)

secret = secrets_manager.get_secrets()

for secret in secret:
    print(secret)