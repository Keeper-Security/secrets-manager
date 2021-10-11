import unittest

from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.utils import get_totp_code
import io
import logging
import re
from contextlib import redirect_stderr


class CoreTest(unittest.TestCase):

    def test_log_level(self):

        """ Test log level.

        It almost impossible to test log level since the unit test initialize the logging. This means
        we have a root handler already. The SDK's basicConfig will not be used. We can set the log level.

        """

        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_CLIENT_KEY, "MY CLIENT KEY")
        config.set(ConfigKeys.KEY_APP_KEY, "MY APP KEY")

        # If the log_level is not set, disable the logger
        SecretsManager(config=config)
        self.assertEqual(True, logging.getLogger(logger_name).disabled, "logging in not disabled")

        with io.StringIO() as buf:
            with redirect_stderr(buf):
                sm = SecretsManager(config=config, log_level="DEBUG")
                self.assertEqual(False, logging.getLogger(logger_name).disabled, "logging in disabled")
                sm.logger.debug("THIS IS DEBUG")
                sm.logger.error("THIS IS ERROR")
                out = buf.getvalue()
                self.assertRegex(out, logger_name, 'did not find the logger name')
                self.assertRegex(out, r'THIS IS DEBUG', "did not find THIS IS DEBUG")
                self.assertRegex(out, r'THIS IS ERROR', "did not find THIS IS ERROR")

                sm = SecretsManager(config=config, log_level=logging.ERROR)
                self.assertEqual(False, logging.getLogger(logger_name).disabled, "logging in disabled")
                sm.logger.debug("NEW DEBUG")
                sm.logger.error("NEW ERROR")
                buf.flush()
                out = buf.getvalue()
                self.assertRegex(out, r'NEW ERROR', "did not find NEW ERROR")
                self.assertFalse(re.search(r'NEW DEBUG', out, re.MULTILINE), 'found NEW DEBUG')



        # Use whatever the logger has been set up as.
        #buf = io.StringIO()
        #logging.getLogger().handlers = [logging.StreamHandler(stream=buf)]


    def test_totp_codes(self):

        """Test TOTP code generation
        """

        # Test default algorithm
        # {Algorithm: "", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=&digits=8&period=30&counter=20000000000'
        code, _, _ = get_totp_code(url)
        self.assertEqual(code, '65353130') # using default algorithm SHA1

        # Test default digits
        # { Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 0}, Output: "353130"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=0&period=30&counter=20000000000'
        code, _, _ = get_totp_code(url)
        self.assertEqual(code, '353130') # using default digits = 6

        # Test default period
        # {Algorithm: "SHA1", Period: 0, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=0&counter=20000000000'
        code, _, _ = get_totp_code(url)
        self.assertEqual(code, '65353130') # using default period = 30

        # Test empty secret
        # {Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "", Digits: 8}, Output: "no secret key provided"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=&issuer=ACME&algorithm=SHA1&digits=8&period=30'
        try:
            code, _, _ = get_totp_code(url)
        except ValueError as err:
            self.assertEqual(str(err), 'TOTP secret not found in URI')

        # Test invalid algorithm
        # { Algorithm: "SHA1024", Period: 30, UnixTime: 0, Secret: "12345678901234567890", Digits: 8}, Output: "invalid algorithm - use one of SHA1/SHA256/SHA512"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1024&digits=8&period=30'
        try:
            code, _, _ = get_totp_code(url)
        except ValueError as err:
            self.assertRegex(str(err), r'Invalid value "[^"]*" for TOTP algorithm, must be SHA1, SHA256 or SHA512', 'did not get correct error message')

        # Test invalid secret
        # { Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "1NVAL1D", Digits: 8}, Output: "bad secret key"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=1NVAL1D&issuer=ACME&algorithm=SHA1&digits=8&period=30'
        try:
            code, _, _ = get_totp_code(url)
        except ValueError as err:
            self.assertEqual(str(err), 'Non-base32 digit found')

        # Check seconds left
        # {Algorithm: "SHA1", Period: 30, UnixTime: 59, Secret: "12345678901234567890", Digits: 8}, Output: "94287082"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30&counter=59'
        code, ttl, _ = get_totp_code(url)
        self.assertEqual("94287082", code)
        self.assertEqual(1, ttl)
        # {Algorithm: "SHA256", Period: 30, UnixTime: 59, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "46119246"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30&counter=59'
        code, ttl, _ = get_totp_code(url)
        self.assertEqual("46119246", code)
        self.assertEqual(1, ttl)
        # {Algorithm: "SHA512", Period: 30, UnixTime: 59, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "90693936"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30&counter=59'
        code, ttl, _ = get_totp_code(url)
        self.assertEqual("90693936", code)
        self.assertEqual(1, ttl)

        # Check different periods - 1 sec. before split
        # {Algorithm: "SHA1", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890", Digits: 8}, Output: "07081804"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30&counter=1111111109'
        code, _, _ = get_totp_code(url)
        self.assertEqual("07081804", code)
        # {Algorithm: "SHA256", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "68084774"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30&counter=1111111109'
        code, _, _ = get_totp_code(url)
        self.assertEqual("68084774", code)
        # {Algorithm: "SHA512", Period: 30, UnixTime: 1111111109, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "25091201"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30&counter=1111111109'
        code, _, _ = get_totp_code(url)
        self.assertEqual("25091201", code)

        # Check different periods - 1 sec. after split
        # {Algorithm: "SHA1", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890", Digits: 8}, Output: "14050471"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30&counter=1111111111'
        code, _, _ = get_totp_code(url)
        self.assertEqual("14050471", code)
        # {Algorithm: "SHA256", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "67062674"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30&counter=1111111111'
        code, _, _ = get_totp_code(url)
        self.assertEqual("67062674", code)
        # {Algorithm: "SHA512", Period: 30, UnixTime: 1111111111, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "99943326"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30&counter=1111111111'
        code, _, _ = get_totp_code(url)
        self.assertEqual("99943326", code)

        # Check different time periods
        # {Algorithm: "SHA1", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890", Digits: 8}, Output: "89005924"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30&counter=1234567890'
        code, _, _ = get_totp_code(url)
        self.assertEqual("89005924", code)
        # {Algorithm: "SHA256", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "91819424"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30&counter=1234567890'
        code, _, _ = get_totp_code(url)
        self.assertEqual("91819424", code)
        # {Algorithm: "SHA512", Period: 30, UnixTime: 1234567890, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "93441116"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30&counter=1234567890'
        code, _, _ = get_totp_code(url)
        self.assertEqual("93441116", code)

        # {Algorithm: "SHA1", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890", Digits: 8}, Output: "69279037"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30&counter=2000000000'
        code, _, _ = get_totp_code(url)
        self.assertEqual("69279037", code)
        # {Algorithm: "SHA256", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "90698825"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30&counter=2000000000'
        code, _, _ = get_totp_code(url)
        self.assertEqual("90698825", code)
        # {Algorithm: "SHA512", Period: 30, UnixTime: 2000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "38618901"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30&counter=2000000000'
        code, _, _ = get_totp_code(url)
        self.assertEqual("38618901", code)

        # {Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30&counter=20000000000'
        code, _, _ = get_totp_code(url)
        self.assertEqual("65353130", code)
        # {Algorithm: "SHA256", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "77737706"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30&counter=20000000000'
        code, _, _ = get_totp_code(url)
        self.assertEqual("77737706", code)
        # {Algorithm: "SHA512", Period: 30, UnixTime: 20000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "47863826"}
        url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30&counter=20000000000'
        code, _, _ = get_totp_code(url)
        self.assertEqual("47863826", code)
