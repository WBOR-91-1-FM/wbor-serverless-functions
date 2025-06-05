"""
Serverless function to notify Discord on GitHub CI failures.

Provided packages:
https://docs.digitalocean.com/products/functions/reference/runtimes/python/#python-311-runtime

If needing to add non-provided packages, use a requirements.txt file following
/#add-packages-with-a-virtual-environment

Author:
- Mason Daugherty <@mdrxy>
"""

import base64
import hashlib
import hmac
import json
import os

import requests

DISCORD_URL = os.getenv("DISCORD_URL")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")


def verify_signature(request_headers: dict, request_body_raw: str, secret: str) -> bool:
    """
    Verifies the GitHub webhook signature using the provided secret.
    Assumes request_headers keys are already normalized (e.g., lowercased).
    """
    if not secret:
        print("Error: GITHUB_WEBHOOK_SECRET is not set. Cannot verify signature.")
        return False

    # GitHub sends the signature in the 'X-Hub-Signature-256' header.
    # We expect 'request_headers' to have lowercase keys.
    signature_header = request_headers.get("x-hub-signature-256")
    if not signature_header:
        print(
            "Error: Request is missing 'x-hub-signature-256' header (after normalization)."
        )
        print(f"Available headers (normalized): {list(request_headers.keys())}")
        return False

    # The signature is of the form "sha256=<actual_signature_hex>"
    try:
        signature_type, signature_value = signature_header.split("=", 1)
    except ValueError:
        print(f"Error: Malformed 'x-hub-signature-256' header: {signature_header}")
        return False

    if signature_type != "sha256":
        print(
            f"Error: Unsupported signature type '{signature_type}'. Expected 'sha256'."
        )
        return False

    # Calculate the expected signature
    # The body needs to be bytes for HMAC
    mac = hmac.new(
        secret.encode("utf-8"),
        msg=request_body_raw.encode(
            "utf-8"
        ),  # request_body_raw must be the decoded string
        digestmod=hashlib.sha256,
    )
    expected_signature = mac.hexdigest()

    # Compare signatures securely to prevent timing attacks
    if not hmac.compare_digest(expected_signature, signature_value):
        print(
            f"Error: Request signature mismatch. Expected: {expected_signature}, "
            f"Got: {signature_value}."
        )
        body_snippet = (
            request_body_raw[:100] + "..."
            if len(request_body_raw) > 100
            else request_body_raw
        )
        print(f"Body used for hashing (first 100 chars): '{body_snippet}'")
        return False

    print("Successfully verified GitHub webhook signature.")
    return True


def main(
    event: dict, context: object = None
) -> (
    dict
):  # pylint: disable=too-many-locals, too-many-statements, too-many-return-statements, too-many-branches
    """
    DigitalOcean Serverless Function main entry point.
    Receives GitHub webhook events and notifies Discord on CI failures.

    Parameters:
    - event (dict): The event data containing headers and raw body.
    - context (object): The context object containing function metadata.
        The object has one method: get_remaining_time_in_millis(),
        which returns the remaining time in milliseconds for the
        function execution.

    Returns:
    - dict: A response object with status code and body. Digital Ocean
        Functions must return a dictionary or nothing at all.
        https://docs.digitalocean.com/products/functions/reference/runtimes/python/#returns
    """
    version = context.function_version  # type: ignore
    print(f"Function version: {version}")
    print(f"Received event keys: {list(event.keys())}")

    if not DISCORD_URL:
        print("Error: DISCORD_URL environment variable not set.")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "DISCORD_URL not configured."}),
        }

    if not GITHUB_WEBHOOK_SECRET:
        print("Error: GITHUB_WEBHOOK_SECRET environment variable not set.")
        return {
            "statusCode": 500,
            "body": json.dumps(
                {"error": "GITHUB_WEBHOOK_SECRET not configured for verification."}
            ),
        }

    http_event_data = event.get("http")
    if not http_event_data or not isinstance(http_event_data, dict):
        print(
            "Error: 'http' object not found in event or is not a dictionary. "
            "Ensure function is configured for 'web: raw' (Raw HTTP)."
        )
        # Log the actual event structure if 'http' is missing or malformed
        print(f"Full event for debugging: {json.dumps(event)}")
        return {
            "statusCode": 400,
            "body": json.dumps(
                {"error": "'http' object missing or malformed in event."}
            ),
        }

    # HTTP headers. Normalize keys to lowercase as HTTP headers are case-insensitive.
    original_headers = http_event_data.get("headers", {})
    normalized_headers = {k.lower(): v for k, v in original_headers.items()}

    raw_body_from_event = http_event_data.get(
        "body"
    )  # This is a String, possibly base64 encoded
    is_base64_encoded = http_event_data.get("isBase64Encoded", False)

    print(
        "Raw body from event.http.body (first 100 chars): "
        f"{str(raw_body_from_event)[:100] if raw_body_from_event is not None else 'None'}"
    )
    print(f"event.http.isBase64Encoded: {is_base64_encoded}")

    if raw_body_from_event is None:
        print(
            "Error: Raw request body ('event.http.body') is missing. "
            "Ensure the webhook is sending a body."
        )
        return {
            "statusCode": 400,
            "body": json.dumps(
                {"error": "Raw request body is missing from http event."}
            ),
        }

    actual_request_body_str: str
    if is_base64_encoded:
        try:
            # The raw_body_from_event is a base64 encoded string.
            # base64.b64decode expects bytes. Encode the string to ASCII (base64 chars are ASCII).
            # The result of b64decode is bytes, then decode these bytes to UTF-8 (common for JSON).
            decoded_bytes = base64.b64decode(raw_body_from_event.encode("ascii"))
            actual_request_body_str = decoded_bytes.decode("utf-8")
            print("Body was successfully base64 decoded.")
        except Exception as e:  # pylint: disable=broad-except
            print(f"Error during base64 decoding or UTF-8 decoding: {e}")
            return {
                "statusCode": 400,
                "body": json.dumps(
                    {"error": "Failed to decode base64 body or decode as UTF-8."}
                ),
            }
    else:
        # If not base64 encoded, assume it's the direct string payload.
        # The documentation says event.http.body is String.
        if not isinstance(raw_body_from_event, str):
            print(
                f"Warning: event.http.body is not a string (type: {type(raw_body_from_event)}) and "
                "not base64 encoded. This is unexpected."
            )
            # Attempt to convert to string, though this might indicate a deeper issue.
            try:
                actual_request_body_str = str(raw_body_from_event)
            except Exception as e:  # pylint: disable=broad-except
                print(f"Error converting non-string body to string: {e}")
                return {
                    "statusCode": 400,
                    "body": json.dumps(
                        {"error": "Body could not be processed as a string."}
                    ),
                }
        else:
            actual_request_body_str = raw_body_from_event
        print("Body used as is (not base64 encoded).")

    # Verify GitHub webhook signature using the (potentially decoded) body string
    # and normalized headers.
    if not verify_signature(
        normalized_headers, actual_request_body_str, GITHUB_WEBHOOK_SECRET
    ):
        # verify_signature already prints detailed errors
        return {
            "statusCode": 403,  # Forbidden
            "body": json.dumps({"error": "Invalid GitHub webhook signature."}),
        }

    # If signature is valid, parse the JSON payload
    try:
        payload = json.loads(actual_request_body_str)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON payload from processed body: {e}")
        print(f"Processed body (first 200 chars): {actual_request_body_str[:200]}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Malformed JSON payload."}),
        }

    # GitHub sends the event type in this header (e.g., 'X-GitHub-Event').
    # We use the normalized (lowercase) key.
    github_event = normalized_headers.get("x-github-event")
    print(
        f"Received GitHub Event (from normalized headers 'x-github-event'): {github_event}"
    )

    message_parts = []
    notify_discord = False
    event_type_processed = ""

    # Process 'workflow_run' event
    # This event is triggered when a workflow run is requested or completed.
    if github_event == "workflow_run":
        event_type_processed = "Workflow Run"
        action = payload.get("action")
        workflow_run_data = payload.get("workflow_run", {})
        conclusion = workflow_run_data.get("conclusion")
        repo_name = payload.get("repository", {}).get("full_name", "N/A")
        workflow_name = workflow_run_data.get("name", "N/A")
        run_url = workflow_run_data.get("html_url", "")
        actor = payload.get("sender", {}).get("login", "N/A")

        print(
            f"Processing workflow_run: action='{action}', conclusion='{conclusion}' for repo "
            f"'{repo_name}', workflow '{workflow_name}'"
        )

        # We are interested in completed runs that have failed.
        if action == "completed" and conclusion == "failure":
            notify_discord = True
            message_parts = [
                "❌ **CI Failure: Workflow Run Failed** ❌",
                f"**Repository:** `{repo_name}`",
                f"**Workflow:** `{workflow_name}`",
                f"**Triggered by:** `{actor}`",
                f"**Status:** `{conclusion.capitalize() if conclusion else 'N/A'}`",
            ]
            if run_url:
                message_parts.append(f"**Details:** [View Workflow Run]({run_url})")
    elif github_event == "workflow_job":
        event_type_processed = "Workflow Job"
        action = payload.get("action")
        workflow_job_data = payload.get("workflow_job", {})
        conclusion = workflow_job_data.get("conclusion")
        repo_name = payload.get("repository", {}).get("full_name", "N/A")
        job_name = workflow_job_data.get("name", "N/A")
        job_url = workflow_job_data.get("html_url", "")
        workflow_name_from_job = workflow_job_data.get("workflow_name", "N/A")
        actor = payload.get("sender", {}).get("login", "N/A")

        print(
            f"Processing workflow_job: action='{action}', conclusion='{conclusion}' for repo "
            f"'{repo_name}', job '{job_name}'"
        )

        if action == "completed" and conclusion == "failure":
            notify_discord = True
            message_parts = [
                "❌ **CI Failure: Workflow Job Failed** ❌",
                # f"**Repository:** `{repo_name}`",
                f"**Workflow:** `{workflow_name_from_job}`",
                f"**Job:** `{job_name}`",
                f"**Triggered by:** `{actor}`",
                f"**Status:** `{conclusion.capitalize() if conclusion else 'N/A'}`",
            ]
            if job_url:
                message_parts.append(f"**Details:** [View Job]({job_url})")
    else:
        # If the event is not one we're interested in, or header is missing.
        print(
            f"Event '{github_event}' is not 'workflow_run' or 'workflow_job', or payload structure "
            "mismatch. No action taken."
        )
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": f"Event '{github_event}' not processed for failure notifications."
                }
            ),
        }

    if notify_discord and message_parts:
        discord_payload = {
            "content": "CI Failure Notification!",
            "embeds": [
                {
                    # Title of embed derived from first line of message_parts
                    "title": message_parts[0],
                    "description": "\n".join(message_parts[1:]),
                    "color": 15158332,  # Red color
                }
            ],
        }
        try:
            response = requests.post(
                DISCORD_URL,
                json=discord_payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            response.raise_for_status()
            print(
                f"Successfully sent notification to Discord for {event_type_processed} failure."
            )
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": f"Notification sent for {event_type_processed} failure."
                    }
                ),
            }
        except requests.exceptions.RequestException as e:
            print(f"Error sending notification to Discord: {e}")
            return {
                "statusCode": 500,
                "body": json.dumps(
                    {"error": f"Failed to send Discord notification: {str(e)}"}
                ),
            }
    else:
        print(
            f"No failure condition met for event '{github_event}'. No notification sent."
        )
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Webhook received, no failure condition met for relevant events."
                }
            ),
        }


if __name__ == "__main__":
    print("Local testing mode...")

    # --- IMPORTANT FOR LOCAL SIGNATURE VERIFICATION ---
    # Set GITHUB_WEBHOOK_SECRET in your environment
    # Example: export GITHUB_WEBHOOK_SECRET="your_test_secret"

    LOCAL_TEST_SECRET = "dummy-secret-for-local-testing"
    if not os.getenv("GITHUB_WEBHOOK_SECRET"):
        print(
            f"Warning: GITHUB_WEBHOOK_SECRET not set. Using local dummy: '{LOCAL_TEST_SECRET}'"
        )
        os.environ["GITHUB_WEBHOOK_SECRET"] = LOCAL_TEST_SECRET
    else:
        LOCAL_TEST_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
        print("Using GITHUB_WEBHOOK_SECRET from environment for testing.")

    GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

    def calculate_test_signature(secret: str, body: str) -> str:
        """
        Calculate a GitHub webhook signature for testing purposes.
        """
        mac = hmac.new(
            secret.encode("utf-8"),
            msg=body.encode("utf-8"),
            digestmod=hashlib.sha256,
        )
        return f"sha256={mac.hexdigest()}"

    # --- Mock DISCORD_URL and requests.post ---
    DISCORD_URL_WAS_SET_EXTERNALLY = bool(os.getenv("DISCORD_URL"))
    if not DISCORD_URL_WAS_SET_EXTERNALLY:
        print("Mocking DISCORD_URL and requests.post for local testing.")
        os.environ["DISCORD_URL"] = "http://mock.discord.url/webhook"

        class MockResponse:  # pylint: disable=missing-class-docstring

            def raise_for_status(self):  # pylint: disable=missing-function-docstring
                pass

        def mock_post(*args, **kwargs):  # pylint: disable=missing-function-docstring
            print(
                f"Mocked requests.post: URL='{args[0]}', "
                f"JSON Payload: {json.dumps(kwargs.get('json', {}), indent=2)}"
            )
            return MockResponse()

        requests.post = mock_post
    else:
        print(f"Using actual DISCORD_URL from environment: {os.getenv('DISCORD_URL')}")

    DISCORD_URL = os.getenv("DISCORD_URL")

    # --- Example Payloads ---
    github_payload_workflow_run_failure = {
        "action": "completed",
        "workflow_run": {
            "id": 1234567890,
            "name": "Build and Test Pipeline",
            "conclusion": "failure",
            "html_url": "https://github.com/org/repo/actions/runs/123",
        },
        "repository": {"full_name": "your-user/your-repo"},
        "sender": {"login": "github-user"},
    }

    # --- Test Cases ---
    print("\n--- Testing Workflow Run Failure (with VALID signature) ---")
    body_str_workflow_run_failure = json.dumps(github_payload_workflow_run_failure)
    VALID_SIGNATURE = calculate_test_signature(
        LOCAL_TEST_SECRET, body_str_workflow_run_failure
    )

    mock_event_workflow_run_failure = {
        "http": {
            "headers": {
                # GitHub typically sends PascalCase, but we normalize to lowercase
                "X-GitHub-Event": "workflow_run",
                "Content-Type": "application/json",
                "X-Hub-Signature-256": VALID_SIGNATURE,
            },
            "body": body_str_workflow_run_failure,
            "isBase64Encoded": False,  # Assuming GitHub sends JSON as raw string
        }
        # 'context' object for local testing
    }

    # Create a dummy context object for local testing
    class DummyContext:  # pylint: disable=missing-class-docstring
        def __init__(self):
            self.function_version = "local_test_v1"

        def get_remaining_time_in_millis(
            self,
        ):  # pylint: disable=missing-function-docstring
            return 30000  # 30 seconds

    result = main(mock_event_workflow_run_failure, DummyContext())
    print(f"Function Result (Workflow Run Failure): {json.dumps(result, indent=2)}")

    # Test 1b: Workflow Run Failure with Base64 Encoded Body
    print("\n--- Testing Workflow Run Failure (Base64 Encoded, VALID signature) ---")
    body_b64_encoded = base64.b64encode(
        body_str_workflow_run_failure.encode("utf-8")
    ).decode("ascii")
    # Signature is calculated on the DECODED body
    VALID_SIG_B64 = calculate_test_signature(
        LOCAL_TEST_SECRET, body_str_workflow_run_failure
    )

    mock_event_workflow_run_failure_b64 = {
        "http": {
            "headers": {
                "X-GitHub-Event": "workflow_run",
                "Content-Type": "application/json",
                "X-Hub-Signature-256": VALID_SIG_B64,
            },
            "body": body_b64_encoded,
            "isBase64Encoded": True,
        }
    }
    result_b64 = main(mock_event_workflow_run_failure_b64, DummyContext())
    print(
        f"Function Result (Workflow Run Failure, Base64): {json.dumps(result_b64, indent=2)}"
    )

    # Test 2: Invalid Signature
    print("\n--- Testing Invalid Signature ---")
    mock_event_invalid_sig = {
        "http": {
            "headers": {
                "X-GitHub-Event": "workflow_run",
                "Content-Type": "application/json",
                "X-Hub-Signature-256": "sha256=invalid0123456789abcdef",
            },
            "body": body_str_workflow_run_failure,
            "isBase64Encoded": False,
        }
    }
    result = main(mock_event_invalid_sig, DummyContext())
    print(f"Function Result (Invalid Signature): {json.dumps(result, indent=2)}")

    # Restore DISCORD_URL if it was not set externally for other potential script runs
    if not DISCORD_URL_WAS_SET_EXTERNALLY:
        del os.environ["DISCORD_URL"]
    if os.environ.get("GITHUB_WEBHOOK_SECRET") == "dummy-secret-for-local-testing":
        del os.environ["GITHUB_WEBHOOK_SECRET"]
