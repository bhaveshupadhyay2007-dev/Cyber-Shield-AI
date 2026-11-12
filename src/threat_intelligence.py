# ============================================================
# CYBER SHIELD AI
# THREAT INTELLIGENCE ENGINE
# ============================================================

import os
import base64
import requests

from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

ENV_PATH = os.path.join(
    BASE_DIR,
    ".env"
)

load_dotenv(ENV_PATH)


# ============================================================
# VIRUSTOTAL API KEY
# ============================================================

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY"
)


# ============================================================
# VIRUSTOTAL API URL
# ============================================================

VIRUSTOTAL_URL = (
    "https://www.virustotal.com/api/v3/urls"
)


# ============================================================
# CHECK IF API IS AVAILABLE
# ============================================================

def is_available():

    return bool(
        VIRUSTOTAL_API_KEY
    )


# ============================================================
# ENCODE URL FOR VIRUSTOTAL
# ============================================================

def encode_url(url):

    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    return encoded


# ============================================================
# CHECK URL WITH VIRUSTOTAL
# ============================================================

def check_url(url):

    if not url:

        return {
            "available": False,
            "detected": False,
            "detections": 0,
            "total_engines": 0,
            "message": "Empty URL"
        }


    # --------------------------------------------------------
    # API KEY NOT CONFIGURED
    # --------------------------------------------------------

    if not VIRUSTOTAL_API_KEY:

        return {
            "available": False,
            "detected": False,
            "detections": 0,
            "total_engines": 0,
            "message":
                "VirusTotal API key not configured"
        }


    headers = {

        "x-apikey":
            VIRUSTOTAL_API_KEY,

        "Accept":
            "application/json"

    }


    try:

        # ----------------------------------------------------
        # SUBMIT URL
        # ----------------------------------------------------

        response = requests.post(

            VIRUSTOTAL_URL,

            headers=headers,

            data={
                "url": url
            },

            timeout=15

        )


        # ----------------------------------------------------
        # API ERROR
        # ----------------------------------------------------

        if response.status_code not in (
            200,
            201
        ):

            return {

                "available": True,

                "detected": False,

                "detections": 0,

                "total_engines": 0,

                "message":
                    "Threat intelligence request failed",

                "status_code":
                    response.status_code

            }


        data = response.json()


        analysis_id = (
            data
            .get("data", {})
            .get("id")
        )


        if not analysis_id:

            return {

                "available": True,

                "detected": False,

                "detections": 0,

                "total_engines": 0,

                "message":
                    "No analysis ID returned"

            }


        # ----------------------------------------------------
        # GET ANALYSIS RESULT
        # ----------------------------------------------------

        analysis_url = (
            "https://www.virustotal.com/api/v3/analyses/"
            + analysis_id
        )


        analysis_response = requests.get(

            analysis_url,

            headers=headers,

            timeout=15

        )


        if analysis_response.status_code != 200:

            return {

                "available": True,

                "detected": False,

                "detections": 0,

                "total_engines": 0,

                "message":
                    "Unable to retrieve threat analysis",

                "status_code":
                    analysis_response.status_code

            }


        analysis_data = (
            analysis_response
            .json()
        )


        attributes = (
            analysis_data
            .get("data", {})
            .get("attributes", {})
        )


        stats = attributes.get(
            "stats",
            {}
        )


        malicious = int(
            stats.get(
                "malicious",
                0
            )
        )


        suspicious = int(
            stats.get(
                "suspicious",
                0
            )
        )


        harmless = int(
            stats.get(
                "harmless",
                0
            )
        )


        undetected = int(
            stats.get(
                "undetected",
                0
            )
        )


        total_engines = (
            malicious
            + suspicious
            + harmless
            + undetected
        )


        detected = (
            malicious > 0
            or suspicious > 0
        )


        # ----------------------------------------------------
        # MESSAGE
        # ----------------------------------------------------

        if malicious > 0:

            message = (
                "Threat intelligence detected "
                "malicious activity"
            )

        elif suspicious > 0:

            message = (
                "Threat intelligence detected "
                "suspicious activity"
            )

        else:

            message = (
                "No malicious detection reported"
            )


        return {

            "available": True,

            "detected": detected,

            "detections":
                malicious + suspicious,

            "malicious":
                malicious,

            "suspicious":
                suspicious,

            "harmless":
                harmless,

            "undetected":
                undetected,

            "total_engines":
                total_engines,

            "message":
                message

        }


    except requests.exceptions.Timeout:

        return {

            "available": True,

            "detected": False,

            "detections": 0,

            "total_engines": 0,

            "message":
                "Threat intelligence request timed out"

        }


    except requests.exceptions.RequestException as error:

        return {

            "available": True,

            "detected": False,

            "detections": 0,

            "total_engines": 0,

            "message":
                "Threat intelligence network error: "
                + str(error)

        }


    except Exception as error:

        return {

            "available": True,

            "detected": False,

            "detections": 0,

            "total_engines": 0,

            "message":
                "Threat intelligence error: "
                + str(error)

        }


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("CYBER SHIELD AI - THREAT INTELLIGENCE TEST")
    print("=" * 60)
    print()

    if is_available():

        print(
            "VirusTotal API key: CONFIGURED"
        )

    else:

        print(
            "VirusTotal API key: NOT CONFIGURED"
        )

    print()

    print(
        "Threat Intelligence module loaded successfully."
    )

    print()