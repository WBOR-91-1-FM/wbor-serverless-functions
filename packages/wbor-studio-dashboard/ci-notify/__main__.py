"""
Serverless function to notify Discord on GitHub CI failures.

Author:
- Mason Daugherty <@mdrxy>
"""

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

    Parameters:
    - request_headers (dict): The headers from the incoming request.
    - request_body_raw (str): The raw body of the request as a string.
    - secret (str): The secret used to sign the webhook payload.

    Returns:
    - bool: True if the signature is valid, False otherwise.
    """
    if not secret:
        print("Error: GITHUB_WEBHOOK_SECRET is not set. Cannot verify signature.")
        return False

    # GitHub sends the signature in the 'X-Hub-Signature-256' header
    signature_header = request_headers.get("x-hub-signature-256")
    if not signature_header:
        print("Error: Request is missing X-Hub-Signature-256 header.")
        return False

    # The signature is of the form "sha256=<actual_signature_hex>"
    try:
        signature_type, signature_value = signature_header.split("=", 1)
    except ValueError:
        print("Error: Malformed X-Hub-Signature-256 header.")
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
        msg=request_body_raw.encode("utf-8"),
        digestmod=hashlib.sha256,
    )
    expected_signature = mac.hexdigest()

    # Compare signatures securely to prevent timing attacks
    if not hmac.compare_digest(expected_signature, signature_value):
        print(
            f"Error: Request signature mismatch. Expected: {expected_signature}, "
            f"Got: {signature_value}"
        )
        return False

    print("Successfully verified GitHub webhook signature.")
    return True


def main(
    args: dict,
) -> (
    dict
):  # pylint: disable=too-many-locals, too-many-statements, too-many-return-statements, too-many-branches
    """
    DigitalOcean Serverless Function main entry point.
    Receives GitHub webhook events and notifies Discord on CI failures.

    Parameters:
    - args (dict): The arguments passed to the function, including
        headers and raw body.

    Returns:
    - dict: A response object with status code and body.
    """
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

    # Extract headers and raw body for signature verification
    # For DigitalOcean Functions configured as "raw HTTP", headers are in '__ow_headers'
    # and the raw request body is in '__ow_body'.
    headers = args.get("__ow_headers", {})
    raw_body = args.get("__ow_body")

    if raw_body is None:  # Check if __ow_body was provided
        print(
            "Error: Raw request body ('__ow_body') not found in arguments. "
            "Ensure function is raw HTTP."
        )
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Raw request body is missing."}),
        }

    # Verify GitHub webhook signature
    if not verify_signature(headers, raw_body, GITHUB_WEBHOOK_SECRET):
        print("Webhook signature verification failed.")
        return {
            "statusCode": 403,  # Forbidden, as the request authenticity could not be verified
            "body": json.dumps({"error": "Invalid GitHub webhook signature."}),
        }

    # If signature is valid, parse the JSON payload from the raw body
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON payload: {e}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Malformed JSON payload."}),
        }

    github_event = headers.get(
        "x-github-event"
    )  # GitHub sends the event type in this header
    print(f"Received GitHub Event: {github_event}")

    message_parts = []
    notify_discord = False
    event_type_processed = ""  # For logging/response messages

    # Process 'workflow_run' event
    # This event is triggered when a workflow run is requested or completed.
    if github_event == "workflow_run":
        event_type_processed = "Workflow Run"
        action = payload.get("action")
        workflow_run_data = payload.get(
            "workflow_run", {}
        )  # Contains details of the workflow run
        conclusion = workflow_run_data.get(
            "conclusion"
        )  # e.g., success, failure, cancelled

        repo_name = payload.get("repository", {}).get("full_name", "N/A")
        workflow_name = workflow_run_data.get("name", "N/A")
        run_url = workflow_run_data.get(
            "html_url", ""
        )  # Direct link to the workflow run
        actor = payload.get("sender", {}).get(
            "login", "N/A"
        )  # User who triggered the event

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
        workflow_job_data = payload.get(
            "workflow_job", {}
        )  # Contains details of the job
        conclusion = workflow_job_data.get("conclusion")

        repo_name = payload.get("repository", {}).get("full_name", "N/A")
        job_name = workflow_job_data.get("name", "N/A")  # Name of the specific job
        job_url = workflow_job_data.get("html_url", "")  # Direct link to the job
        workflow_name_from_job = workflow_job_data.get("workflow_name", "N/A")
        actor = payload.get("sender", {}).get("login", "N/A")

        print(
            f"Processing workflow_job: action='{action}', conclusion='{conclusion}' for repo "
            f"'{repo_name}', job '{job_name}'"
        )

        # We are interested in completed jobs that have failed.
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
            "statusCode": 200,  # Acknowledge receipt but indicate no action taken for this event
            "body": json.dumps(
                {
                    "message": f"Event '{github_event}' not processed for failure notifications."
                }
            ),
        }

    if notify_discord and message_parts:
        discord_payload = {
            "content": "CI Failure!",
            "embeds": [
                {
                    "title": f"CI Failure: {event_type_processed} Failed",
                    "description": "\n".join(
                        message_parts[1:]
                    ),  # Exclude the first line since used as title
                    "color": 15158332,  # Red color
                }
            ],
        }
        try:
            response = requests.post(
                DISCORD_URL,
                json=discord_payload,
                headers={"Content-Type": "application/json"},
                timeout=10,  # Add a timeout for the request
            )
            # Raise an exception for HTTP errors (4xx or 5xx status codes)
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
            # Return an error response if Discord communication fails
            return {
                "statusCode": 500,
                "body": json.dumps(
                    {"error": f"Failed to send Discord notification: {str(e)}"}
                ),
            }
    else:
        # If no failure condition was met for the processed events.
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
    # For verify_signature to work, set GITHUB_WEBHOOK_SECRET in your environment
    # For example, in your terminal before running the script:
    # export GITHUB_WEBHOOK_SECRET="your_test_secret"
    #
    # If you want verify_signature to PASS, you'll also need to provide a
    # correct 'x-hub-signature-256' in __ow_headers for each test case,
    # calculated using 'your_test_secret' and the __ow_body of that test case.
    #
    # If GITHUB_WEBHOOK_SECRET is not set, your function will try to return a 500 error.
    # If it's set, but the signature is missing or incorrect, it will return a 403 error.
    # Both are valid test paths.

    # Set a dummy secret for local testing if not set in environment,
    # so the function doesn't immediately exit due to missing secret.
    # You'd still need to generate a valid signature if you want verification to pass.
    LOCAL_TEST_SECRET = "dummy-secret-for-local-testing"
    if not os.getenv("GITHUB_WEBHOOK_SECRET"):
        print("Warning: GITHUB_WEBHOOK_SECRET not set in environment.")
        print(
            f"Using a local dummy secret ('{LOCAL_TEST_SECRET}') for GITHUB_WEBHOOK_SECRET for "
            "testing purposes."
        )
        print(
            "Signature verification will likely fail unless you provide a matching "
            "x-hub-signature-256 header."
        )
        os.environ["GITHUB_WEBHOOK_SECRET"] = (
            LOCAL_TEST_SECRET  # Use this for the current run
        )
    else:
        LOCAL_TEST_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
        print("Using GITHUB_WEBHOOK_SECRET from environment for testing.")

    # Function to calculate a GitHub signature for testing
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

    # --- Mock DISCORD_URL ---
    # os.environ["DISCORD_URL"] = "YOUR_TEST_DISCORD_WEBHOOK_URL"
    if not os.getenv("DISCORD_URL"):
        print(
            "Skipping actual Discord send: DISCORD_URL not set for local test. "
            "Mocking requests.post."
        )

        class MockResponse:
            """
            Defines a mock response object to simulate requests.post behavior.
            This is used to avoid actual HTTP requests during local testing.
            """

            def raise_for_status(self):
                """
                Simulate raising an HTTPError for non-2xx responses.
                For this mock, we assume all requests succeed.
                """
                # Simulate no error

        def mock_post(*args, **kwargs):
            """
            Simulates requests.post for local testing.
            Prints the URL and JSON payload instead of sending a request.
            """
            print(
                f"Mocked requests.post: Called with URL '{args[0]}', "
                f"JSON Payload: {json.dumps(kwargs.get('json', {}), indent=2)}"
            )
            return MockResponse()

        requests.post = mock_post  # Monkey patch requests.post

    # Ensure DISCORD_URL is correctly fetched after potential os.environ update by mock_post setup
    DISCORD_URL = os.getenv("DISCORD_URL")

    # --- Example Payloads ---
    github_payload_workflow_run_failure = {
        "action": "completed",
        "workflow_run": {
            "id": 1234567890,
            "name": "Build and Test Pipeline",
            "conclusion": "failure",
            "html_url": "https://github.com/your-user/your-repo/actions/runs/1234567890",
            "updated_at": "2024-01-15T10:00:00Z",
        },
        "repository": {"full_name": "your-user/your-repo"},
        "sender": {"login": "github-user"},
    }

    github_payload_workflow_job_failure = {
        "action": "completed",
        "workflow_job": {
            "id": 9876543210,
            "name": "Unit Tests",
            "conclusion": "failure",
            "html_url": "https://github.com/your-user/your-repo/actions/runs/1234567890/job/9876543210",  # pylint: disable=line-too-long
            "workflow_name": "Build and Test Pipeline",
        },
        "repository": {"full_name": "your-user/another-repo"},
        "sender": {"login": "another-user"},
    }

    github_payload_workflow_run_success = {
        "action": "completed",
        "workflow_run": {
            "conclusion": "success",
            "name": "Deployment Workflow",
            "html_url": "https://github.com/your-user/your-repo/actions/runs/111222333",
        },
        "repository": {"full_name": "your-user/successful-repo"},
        "sender": {"login": "ops-bot"},
    }

    github_payload_other_event = {  # e.g., a push event
        "ref": "refs/heads/main",
        "repository": {"full_name": "your-user/some-repo"},
        "pusher": {"name": "test-user"},  # Example push event body
    }

    # --- Test Cases ---

    # Test 1: Workflow Run Failure
    print(
        "\n--- Testing Workflow Run Failure (Signature will likely fail unless "
        "GITHUB_WEBHOOK_SECRET is set and signature below is correct) ---"
    )
    body_str_workflow_run_failure = json.dumps(github_payload_workflow_run_failure)
    # For this test to pass signature verification, generate signature with LOCAL_TEST_SECRET
    # test_sig_workflow_run = calculate_test_signature(LOCAL_TEST_SECRET,
    #   body_str_workflow_run_failure)
    mock_args_workflow_run_failure = {
        "__ow_headers": {
            "x-github-event": "workflow_run",
            "content-type": "application/json",
            # Replace "dummy_signature" with test_sig_workflow_run if you want to test valid
            # signature path
            "x-hub-signature-256": "sha256=dummy_signature_that_will_fail_verification",
        },
        "__ow_body": body_str_workflow_run_failure,
    }
    result = main(mock_args_workflow_run_failure)
    print(f"Function Result (Workflow Run Failure): {json.dumps(result, indent=2)}")

    # Test 1b: Workflow Run Failure (WITH VALID SIGNATURE if GITHUB_WEBHOOK_SECRET is set)
    if os.getenv(
        "GITHUB_WEBHOOK_SECRET"
    ):  # Only run this if secret is available to calculate a valid sig
        print(
            "\n--- Testing Workflow Run Failure (WITH DYNAMICALLY GENERATED VALID SIGNATURE) ---"
        )
        body_str_workflow_run_failure_valid_sig = json.dumps(
            github_payload_workflow_run_failure
        )
        VALID_SIGNATURE = calculate_test_signature(
            LOCAL_TEST_SECRET, body_str_workflow_run_failure_valid_sig
        )
        mock_args_workflow_run_failure_valid_sig = {
            "__ow_headers": {
                "x-github-event": "workflow_run",
                "content-type": "application/json",
                "x-hub-signature-256": VALID_SIGNATURE,
            },
            "__ow_body": body_str_workflow_run_failure_valid_sig,
        }
        result = main(mock_args_workflow_run_failure_valid_sig)
        print(
            f"Function Result (Workflow Run Failure with Valid Sig): {json.dumps(result, indent=2)}"
        )

    # Test 2: Workflow Job Failure
    print("\n--- Testing Workflow Job Failure (Signature will likely fail) ---")
    body_str_workflow_job_failure = json.dumps(github_payload_workflow_job_failure)
    mock_args_workflow_job_failure = {
        "__ow_headers": {
            "x-github-event": "workflow_job",
            "x-hub-signature-256": "sha256=dummy_signature",
        },
        "__ow_body": body_str_workflow_job_failure,
    }
    result = main(mock_args_workflow_job_failure)
    print(f"Function Result (Workflow Job Failure): {json.dumps(result, indent=2)}")

    # Test 3: Workflow Run Success (should not notify)
    print(
        "\n--- Testing Workflow Run Success (Signature will likely fail, but logic should not "
        "notify) ---"
    )
    body_str_workflow_run_success = json.dumps(github_payload_workflow_run_success)
    mock_args_workflow_run_success = {
        "__ow_headers": {
            "x-github-event": "workflow_run",
            "x-hub-signature-256": "sha256=dummy_signature",
        },
        "__ow_body": body_str_workflow_run_success,
    }
    result = main(mock_args_workflow_run_success)
    print(f"Function Result (Workflow Run Success): {json.dumps(result, indent=2)}")

    # Test 4: Irrelevant Event (e.g., push)
    print(
        "\n--- Testing Irrelevant Event (Signature will likely fail, but logic should not "
        "notify) ---"
    )
    body_str_other_event = json.dumps(github_payload_other_event)
    mock_args_other_event = {
        "__ow_headers": {
            "x-github-event": "push",  # Not workflow_run or workflow_job
            "x-hub-signature-256": "sha256=dummy_signature",
        },
        "__ow_body": body_str_other_event,
    }
    result = main(mock_args_other_event)
    print(f"Function Result (Irrelevant Event): {json.dumps(result, indent=2)}")

    # Test 5: GITHUB_WEBHOOK_SECRET not set (simulated by temporarily unsetting)
    # This test is a bit tricky if we globally set it above. Best to test this by
    # running the script in an environment where GITHUB_WEBHOOK_SECRET is truly unset.
    # However, we can simulate the condition where the `secret` parameter to `verify_signature` is
    #   None.
    # Your function already has:
    #   if not GITHUB_WEBHOOK_SECRET: print("Error: GITHUB_WEBHOOK_SECRET environment variable not
    #   set.") ...
    # So, if you run this script WITHOUT `export GITHUB_WEBHOOK_SECRET=...` first,
    # and without the fallback `os.environ["GITHUB_WEBHOOK_SECRET"] = LOCAL_TEST_SECRET`
    # this path should be tested.
    # The current setup with LOCAL_TEST_SECRET fallback makes this specific test case harder to
    # isolate here.
    print(
        "\n--- Simulating GITHUB_WEBHOOK_SECRET not effectively set for verify_signature ---"
    )
    print(
        "(To test this path properly, run without GITHUB_WEBHOOK_SECRET env var and remove the "
        "local fallback assignment)"
    )
    # We can't easily unset os.environ for just one call within this script if it was set by the
    # script itself.
    # This test case is better run by controlling the actual environment.
    # However, if the GITHUB_WEBHOOK_SECRET in os.environ is empty, verify_signature should catch it
    original_secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
    if original_secret is not None:  # It was set (either by env or our fallback)
        os.environ["GITHUB_WEBHOOK_SECRET"] = ""  # Simulate it being present but empty
        print("Temporarily set GITHUB_WEBHOOK_SECRET to empty string for one test")
        body_str_temp = json.dumps(github_payload_workflow_run_failure)
        mock_args_temp = {
            "__ow_headers": {
                "x-github-event": "workflow_run",
                "x-hub-signature-256": "sha256=any",
            },
            "__ow_body": body_str_temp,
        }
        result = main(mock_args_temp)
        print(
            f"Function Result (GITHUB_WEBHOOK_SECRET empty): {json.dumps(result, indent=2)}"
        )
        os.environ["GITHUB_WEBHOOK_SECRET"] = original_secret  # Restore it
    else:
        print("Skipping test for empty GITHUB_WEBHOOK_SECRET as it was never set.")

    # Test 6: DISCORD_URL not set (simulate by unsetting)
    print("\n--- Testing with DISCORD_URL unset (if not already mocked) ---")
    original_discord_url = DISCORD_URL
    # To truly test this, requests.post should not be mocked AND DISCORD_URL should be None
    # If requests.post is mocked, this test mostly checks the print statement.
    # If DISCORD_URL is None, the function should return an error before trying to post.
    if original_discord_url is not None:  # If it was set
        # Temporarily modify the global DISCORD_URL that main() sees
        # This is a bit of a hack for testing; proper dependency injection is cleaner
        globals_backup_discord_url = globals().get("DISCORD_URL")
        globals()["DISCORD_URL"] = None

        # Also need to unset from os.environ if main() re-fetches it via os.getenv()
        original_os_discord_url = os.environ.get("DISCORD_URL")
        if "DISCORD_URL" in os.environ:
            del os.environ["DISCORD_URL"]

        print(
            "Temporarily unset DISCORD_URL for one test. Mocked post: "
            f"{requests.post.__name__ == 'mock_post'}"
        )

        body_str_temp_discord = json.dumps(github_payload_workflow_run_failure)
        mock_args_temp_discord_valid_sig = {  # Use a payload that would normally send
            "__ow_headers": {
                "x-github-event": "workflow_run",
                "x-hub-signature-256": (
                    calculate_test_signature(LOCAL_TEST_SECRET, body_str_temp_discord)
                    if LOCAL_TEST_SECRET
                    else "sha256=dummy"
                ),
            },
            "__ow_body": body_str_temp_discord,
        }
        result = main(mock_args_temp_discord_valid_sig)
        print(f"Function Result (DISCORD_URL unset): {json.dumps(result, indent=2)}")

        globals()["DISCORD_URL"] = globals_backup_discord_url  # Restore global
        if original_os_discord_url is not None:
            os.environ["DISCORD_URL"] = original_os_discord_url  # Restore os.environ

    else:  # DISCORD_URL was already None/unset
        print("DISCORD_URL is already unset. Running test assuming it's None.")
        body_str_temp_discord = json.dumps(github_payload_workflow_run_failure)
        mock_args_temp_discord_valid_sig = {  # Use a payload that would normally send
            "__ow_headers": {
                "x-github-event": "workflow_run",
                "x-hub-signature-256": (
                    calculate_test_signature(LOCAL_TEST_SECRET, body_str_temp_discord)
                    if LOCAL_TEST_SECRET
                    else "sha256=dummy"
                ),
            },
            "__ow_body": body_str_temp_discord,
        }
        result = main(mock_args_temp_discord_valid_sig)
        print(f"Function Result (DISCORD_URL unset): {json.dumps(result, indent=2)}")
