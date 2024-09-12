from selenium import webdriver
import platform
from selenium.common.exceptions import NoAlertPresentException,UnexpectedAlertPresentException
import time


def is_linux():
    return platform.system() == 'Linux'

if is_linux():
    from selenium.webdriver.chrome.options import Options
    options = Options()
    options.binary_location = "/usr/bin/chromium"
else:
    options = webdriver.ChromeOptions()



options.add_argument("--headless")  # Run Chrome in headless mode
options.add_argument("--disable-gpu")  # Disable GPU acceleration (optional)
options.add_argument("--no-sandbox") 
# Initialize the WebDriver (assuming Chrome)

def validate_js_alert(url):

    driver = webdriver.Chrome(options=options)
    try:
        # Navigate to the URL
        #print(url)
        driver.get(url)

        # Wait a few seconds to ensure the alert has time to appear
        time.sleep(3)

        try:
            # Switch to the alert
            alert = driver.switch_to.alert

            # Get the text in the alert

            # Accept (close) the alert
            alert.accept()

            #print(f"Alert detected: {alert_text}\n{url}")
            driver.quit()
            return {'success':True,'url':url}

        except NoAlertPresentException:
            # No alert was found
            #print("No alert detected")
            return {'success':False,'url':url}
    except UnexpectedAlertPresentException as e:
        # Handle the unexpected alert
        return {'success':True,'url':url}
    except NoAlertPresentException:
        return {'success':False,'url':url}
    except Exception as e:
        #pass
        print(e)
    


if __name__ == "__main__":
    # Example usage
    url_to_test = "http://testphp.vulnweb.com/hpp/?pp=test%22%3E%3Cimg%20src=x%20onerror=alert(1)%3El"
    result = validate_js_alert(url_to_test)

    if result:
        print("JavaScript alert was generated.")
    else:
        print("No JavaScript alert was generated.")
