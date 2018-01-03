#!/usr/bin/env python3.6

from selenium import webdriver # type: ignore
from selenium.webdriver.remote.webdriver import WebDriver # type: ignore
from selenium.webdriver import Chrome, Firefox, PhantomJS # type: ignore
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities # type: ignore
from selenium.common.exceptions import TimeoutException, NoSuchElementException # type: ignore

from subprocess import check_call, CalledProcessError

import config
import logging
import urllib.request
from urllib.error import URLError
from ssl import CertificateError
import socket
from wireless import Wireless

logger = logging.getLogger('BTReloginHelper')

BT_WIFI_SSID = "BTWi-fi"
BT_WIFI_WITH_FON_SSID = "BTWifi-with-FON"

BT_WIFIS = [BT_WIFI_SSID, BT_WIFI_WITH_FON_SSID]


def get_wifi_name():
    return str(Wireless().current())


def get_login_click_handler(wifi_ssid: str):

    def login_click_bt(driver: WebDriver, username: str, password: str):
        if "You’re now logged in to BT Wi-fi" in driver.page_source:
            logger.warning("Already logged... weird, doing nothing")
            return True

        # this is the weird bug 'wifi access has expired'
        if len(driver.find_elements_by_link_text("Buy more time")) > 0:
            driver.find_element_by_link_text("Logout").click()
            # TODO how to wait?

        driver.find_element_by_id("username").send_keys(username)
        driver.find_element_by_id("password-password").send_keys(password)
        driver.find_element_by_class_name("lgnbtn").click()
        return True

    def login_click_with_fon(driver: WebDriver, username: str, password: str):
        if "You’re now logged in to BT Wi-fi" in driver.page_source:
            logger.warning("Already logged... weird, doing nothing")
            return True

        # this is the weird bug 'wifi access has expired'
        if len(driver.find_elements_by_link_text("Buy more time")) > 0:
            driver.find_element_by_link_text("Logout").click()
            # TODO how to wait?

        # select 'BT Wi-fi
        driver.find_element_by_id("provider2").click()

        # for some reason every bt wifi option (FON/Broadband/Wifi) has its own form
        # so we have to find the one responsible for BT WiFI login
        login_form = driver.find_element_by_id('wifi_logon_form')

        login_form.find_element_by_id("username").send_keys(username)
        login_form.find_element_by_id("password").send_keys(password)
        login_form.find_element_by_id("loginbtn").click()
        return True

    if wifi_ssid == BT_WIFI_SSID:
        return login_click_bt
    elif wifi_ssid == BT_WIFI_WITH_FON_SSID:
        return login_click_with_fon
    else:
        raise ValueError(f"Sorry, {wifi_ssid} reconnect is not yet supported")


class ReloginHelper:
    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password

    def _login(self, driver: WebDriver) -> bool:
        # https://stackoverflow.com/a/27417860/706389
        BT_TIMEOUT = 5 # seconds
        driver.implicitly_wait(BT_TIMEOUT)
        driver.set_page_load_timeout(BT_TIMEOUT)
        BT_PAGE = "https://www.btopenzone.com:8443/home"
        driver.get(BT_PAGE)
        # TODO huh, on VPN it shows 'you may have lost connection'. weird.

        handler = get_login_click_handler(get_wifi_name())
        return handler(driver, self.username, self.password)


    def _check_connected(self) -> bool:
        # testing for internet connection is hard..
        # ideally you should just ping, but on BT DNS works once you are connected, you don't have to log in
        # so we load a small http page and check its content to see if we have access to Internet
        try:
            # TODO FIXME huh, httpbin doesn't always work.. 'name or service not available' exception. or is it bt wifi being stupid?
            TIMEOUT_SECONDS = 5
            TEST_URL = "https://httpbin.org/get?hasinternet=True"
            # TEST_URL = "http://www.google.com:81" # test page
            url = urllib.request.urlopen(TEST_URL, None, TIMEOUT_SECONDS)
            data = str(url.read(), 'utf-8')
            return "hasinternet" in data
        except CertificateError:
            logger.info("Certificate error while retreiving test page...")
            return False
        except URLError as e:
            if 'timed out' in str(e.reason):
                logger.info("Timeout while retreiving test page...")
                return False
            else:
                raise e
        except socket.timeout:
            logger.info("Timeout while retreiving test page...")
            return False

    def _try_login_once(self) -> bool:
        driver = webdriver.PhantomJS(
            executable_path=config.PHANTOMJS_BIN,
            # sometimes returns empty page...
            # see https://stackoverflow.com/a/36159299/706389
            service_args=['--ignore-ssl-errors=true', '--ssl-protocol=TLSv1']
        )
        try:
            driver.maximize_window()
            try:
                res = self._login(driver)
                if res:
                    logger.info("Logged in via PhantomJS")
                else:
                    logger.warning("Failed to log in via PhantomJS")
                return res
            except TimeoutException as e:
                logger.warning("Timeout while interacting with page...")
                return False
            except CertificateError as e:
                logger.warning("Certificate error while interacting with page...")
                return False
        finally:
            driver.quit()

    def try_login(self, max_attempts=5) -> bool:
        attempt = 0
        while attempt < max_attempts:
            attempt += 1
            if self._check_connected():
                logger.debug("Connected.. no action needed")
                return True

            logger.info(f"Not connected, trying to login with webdriver, attempt {attempt}")
            res = self._try_login_once()
            if res:
                return True
        return False

    """
       Somethimes it just gets stuck and even wifi login page is not responding... in this case reconnecting wifi is to the rescue.
    """
    def reconnect_wifi(self):
        current_wifi = get_wifi_name()

        if current_wifi not in BT_WIFIS:
            logger.warning(f"Sorry, only reconnecting to BT wifi-s are supported. Current network: {current_wifi}")

        logger.info(f"Disabling connection...")
        try:
            check_call(["nmcli", "con", "down", current_wifi])
        except CalledProcessError as e:
            logger.warning("Error while disabling connection...")
            logger.exception(e)
            logger.warning("Still will try to reconnect..")
        logger.info(f"sleeping...")
        import time
        time.sleep(5)
        logger.info(f"Enabling connection...")
        check_call(["nmcli", "con", "up", current_wifi])
        # TODO sanity check that we are connected to BT wifi?

    def fix_wifi_if_necessary(self):
        MAX_ATTEMPTS = 5
        attempt = 0
        while attempt < MAX_ATTEMPTS:
            attempt += 1
            logged: bool = False
            try:
                logger.debug("Trying to connect via PhantomJS..")
                logged = self.try_login()
            except URLError as e:
                if 'Name or service not known' in str(e):
                    # usually means we have to reset wifi connection...
                    logger.exception(e)
                    logged = False
                elif 'Connection refused' in str(e):
                    # weird thing... probably have to reconnect to wifi as well..
                    logger.exception(e)
                else:
                    raise e
            except NoSuchElementException as e:
                # TODO this is usually 'your wifi access has expired page', might be a good idea to click log out?
                logger.exception(e)
            if logged:
                return
            logger.warning(f"Could not log in via webdriver, attempt {attempt} to reconnect to wifi")
            self.reconnect_wifi()
        logger.error("Could not recconnect. Sorry :(")


def main():

    helper = ReloginHelper(config.USERNAME, config.PASSWORD)
    helper.fix_wifi_if_necessary()


if __name__ == '__main__':
    main()
