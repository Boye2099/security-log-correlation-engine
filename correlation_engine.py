import csv
from collections import defaultdict
from datetime import datetime, timedelta


# ============================================================
# SECURITY LOG CORRELATION ENGINE
# ============================================================
#
# A defensive security project that correlates different
# security events into timelines and identifies combinations
# of activity that may require investigation.
#
# The project uses synthetic security logs.
#
# Event types used:
#   AUTH_FAILED
#   AUTH_SUCCESS
#   POWERSHELL
#   NETWORK_CONNECTION
#
# The goal is to move beyond looking at individual events
# and instead investigate related activity as a sequence.
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

LOG_FILE = "security_logs.csv"

# Maximum amount of time allowed between related events.
CORRELATION_WINDOW = timedelta(minutes=10)

# Number of failed logins required to trigger correlation.
FAILED_LOGIN_THRESHOLD = 3

# Ports commonly associated with Windows administration
# in this training dataset.
ADMIN_PORTS = {
    135,
    139,
    445,
    3389
}

# Accounts considered privileged in this dataset.
PRIVILEGED_ACCOUNTS = {
    "admin",
    "administrator",
    "david"
}


# ============================================================
# DATA STORAGE
# ============================================================

events = []

user_events = defaultdict(list)


# ============================================================
# LOAD SECURITY LOG
# ============================================================

try:

    with open(
        LOG_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            # Convert the timestamp into a datetime object.
            row["datetime"] = datetime.strptime(
                row["time"],
                "%Y-%m-%d %H:%M:%S"
            )

            # Convert event ID to an integer when present.
            if row["event_id"]:
                row["event_id"] = int(row["event_id"])

            # Convert destination port to integer when present.
            if row["destination_port"]:
                row["destination_port"] = int(
                    row["destination_port"]
                )
            else:
                row["destination_port"] = None

            events.append(row)

except FileNotFoundError:

    print(f"[ERROR] Could not find {LOG_FILE}.")
    print("Make sure security_logs.csv is in the same directory.")

    raise SystemExit


# ============================================================
# SORT EVENTS
# ============================================================

events.sort(
    key=lambda event: event["datetime"]
)


# ============================================================
# GROUP EVENTS BY USER
# ============================================================

for event in events:

    username = event["username"]

    user_events[username].append(event)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_privileged_account(username):
    """
    Check whether an account is considered privileged.
    """

    return username.lower() in {
        account.lower()
        for account in PRIVILEGED_ACCOUNTS
    }


def get_recent_events(
    account_events,
    current_time,
    event_type=None
):
    """
    Return events that occurred within the correlation
    window before the current event.
    """

    window_start = current_time - CORRELATION_WINDOW

    recent = [
        event
        for event in account_events
        if window_start <= event["datetime"] <= current_time
    ]

    if event_type:

        recent = [
            event
            for event in recent
            if event["event_type"] == event_type
        ]

    return recent


def get_severity(score):
    """
    Convert a risk score into a severity level.
    """

    if score >= 80:
        return "HIGH"

    if score >= 50:
        return "MEDIUM"

    return "LOW"


# ============================================================
# DETECTION STORAGE
# ============================================================

alerts = []

risk_scores = defaultdict(int)

risk_reasons = defaultdict(list)


# ============================================================
# DETECTION 1
# MULTIPLE FAILED LOGINS
# ============================================================

for username, account_event_list in user_events.items():

    for event in account_event_list:

        if event["event_type"] != "AUTH_FAILED":
            continue

        recent_failures = get_recent_events(
            account_event_list,
            event["datetime"],
            "AUTH_FAILED"
        )

        if len(recent_failures) >= FAILED_LOGIN_THRESHOLD:

            alerts.append({
                "username": username,
                "time": event["time"],
                "type": "Repeated Authentication Failures",
                "details": (
                    f"{len(recent_failures)} failed "
                    f"logins within 10 minutes"
                )
            })

            risk_scores[username] += 25

            risk_reasons[username].append(
                "repeated authentication failures"
            )

            # One alert is enough for this detection.
            break


# ============================================================
# DETECTION 2
# FAILED LOGINS FOLLOWED BY SUCCESS
# ============================================================

for username, account_event_list in user_events.items():

    for event in account_event_list:

        if event["event_type"] != "AUTH_SUCCESS":
            continue

        recent_failures = get_recent_events(
            account_event_list,
            event["datetime"],
            "AUTH_FAILED"
        )

        if len(recent_failures) >= FAILED_LOGIN_THRESHOLD:

            alerts.append({
                "username": username,
                "time": event["time"],
                "type": "Failed Logins Followed By Success",
                "details": (
                    f"{len(recent_failures)} failed logins "
                    f"before successful authentication"
                )
            })

            risk_scores[username] += 30

            risk_reasons[username].append(
                "failed authentication followed by success"
            )

            break


# ============================================================
# DETECTION 3
# POWERSHELL AFTER SUSPICIOUS AUTHENTICATION
# ============================================================

for username, account_event_list in user_events.items():

    for event in account_event_list:

        if event["event_type"] != "POWERSHELL":
            continue

        recent_failures = get_recent_events(
            account_event_list,
            event["datetime"],
            "AUTH_FAILED"
        )

        recent_successes = get_recent_events(
            account_event_list,
            event["datetime"],
            "AUTH_SUCCESS"
        )

        if (
            len(recent_failures) >= FAILED_LOGIN_THRESHOLD
            and recent_successes
        ):

            alerts.append({
                "username": username,
                "time": event["time"],
                "type": "Authentication + PowerShell Correlation",
                "details": (
                    "PowerShell activity occurred after "
                    "suspicious authentication activity"
                )
            })

            risk_scores[username] += 25

            risk_reasons[username].append(
                "PowerShell activity correlated with authentication"
            )

            break


# ============================================================
# DETECTION 4
# ADMINISTRATIVE NETWORK CONNECTION
# ============================================================

for username, account_event_list in user_events.items():

    for event in account_event_list:

        if event["event_type"] != "NETWORK_CONNECTION":
            continue

        destination_port = event["destination_port"]

        if destination_port not in ADMIN_PORTS:
            continue

        recent_successes = get_recent_events(
            account_event_list,
            event["datetime"],
            "AUTH_SUCCESS"
        )

        if recent_successes:

            alerts.append({
                "username": username,
                "time": event["time"],
                "type": "Authentication + Administrative Network Activity",
                "details": (
                    f"Network connection to port "
                    f"{destination_port} after authentication"
                )
            })

            risk_scores[username] += 20

            risk_reasons[username].append(
                "administrative network activity after authentication"
            )

            break


# ============================================================
# DETECTION 5
# PRIVILEGED ACCOUNT ACTIVITY
# ============================================================

for username, account_event_list in user_events.items():

    if not is_privileged_account(username):
        continue

    if account_event_list:

        risk_scores[username] += 20

        risk_reasons[username].append(
            "privileged account activity"
        )

        alerts.append({
            "username": username,
            "time": account_event_list[0]["time"],
            "type": "Privileged Account Activity",
            "details": (
                "Security activity was generated by a "
                "privileged account"
            )
        })


# ============================================================
# DETECTION 6
# MULTIPLE INDICATORS
# ============================================================

for username, reasons in risk_reasons.items():

    unique_reasons = list(
        dict.fromkeys(reasons)
    )

    risk_reasons[username] = unique_reasons

    # Multiple independent indicators provide additional
    # context and increase investigation priority.
    if len(unique_reasons) >= 3:

        risk_scores[username] += 15

        risk_reasons[username].append(
            "multiple security indicators correlated"
        )


# ============================================================
# DISPLAY HEADER
# ============================================================

print("\n" + "=" * 75)
print("SECURITY LOG CORRELATION ENGINE")
print("=" * 75)

print(f"\nTotal events analyzed: {len(events)}")
print("Correlation window: 10 minutes")
print(
    f"Failed login threshold: "
    f"{FAILED_LOGIN_THRESHOLD}"
)


# ============================================================
# DISPLAY ALERTS
# ============================================================

print("\n[DETECTED SECURITY EVENTS]")
print("-" * 75)

if not alerts:

    print("No suspicious activity detected.")

else:

    for number, alert in enumerate(
        alerts,
        start=1
    ):

        print(f"\nAlert #{number}")
        print(f"  Account: {alert['username']}")
        print(f"  Time:    {alert['time']}")
        print(f"  Type:    {alert['type']}")
        print(f"  Details: {alert['details']}")


# ============================================================
# DISPLAY RISK SCORES
# ============================================================

print("\n" + "=" * 75)
print("RISK ASSESSMENT")
print("=" * 75)

if not risk_scores:

    print("\nNo accounts require further investigation.")

else:

    sorted_accounts = sorted(
        risk_scores.items(),
        key=lambda item: item[1],
        reverse=True
    )

    for username, score in sorted_accounts:

        severity = get_severity(score)

        print(f"\nAccount: {username}")
        print(f"Risk Score: {score}")
        print(f"Severity: {severity}")

        print("Indicators:")

        for reason in risk_reasons[username]:

            print(f"  - {reason}")


# ============================================================
# ACCOUNT TIMELINES
# ============================================================

print("\n" + "=" * 75)
print("ACCOUNT TIMELINES")
print("=" * 75)

for username, account_event_list in user_events.items():

    print(f"\n{username}")
    print("-" * 55)

    for event in account_event_list:

        details = event["event_type"]

        if event["event_type"] == "NETWORK_CONNECTION":

            details += (
                f" -> {event['destination_ip']}:"
                f"{event['destination_port']}"
            )

        elif event["event_type"] == "POWERSHELL":

            details += (
                f" -> {event['process']}"
            )

        print(
            f"{event['time']} | "
            f"{details}"
        )


# ============================================================
# INVESTIGATION SUMMARY
# ============================================================

print("\n" + "=" * 75)
print("INVESTIGATION SUMMARY")
print("=" * 75)

high_risk_accounts = [
    username
    for username, score in risk_scores.items()
    if score >= 80
]

if high_risk_accounts:

    print("\nAccounts requiring priority investigation:")

    for username in high_risk_accounts:

        print(
            f"  - {username} "
            f"(Risk Score: {risk_scores[username]})"
        )

else:

    print(
        "\nNo account reached the high-risk threshold."
    )


print("\nAnalysis complete.")
