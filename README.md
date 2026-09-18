# Security Log Correlation Engine

A Python security project I built to practice correlating different types of security events.

The idea behind the project is simple: instead of looking at one log entry at a time, it connects related events and builds a timeline that can give more context during an investigation.

The project uses synthetic security logs.

## What it does

The engine looks for patterns involving:

* Failed authentication attempts
* Successful authentication
* PowerShell activity
* Network connections
* Privileged accounts
* Multiple suspicious indicators occurring together

It then creates alerts, assigns a basic risk score, and shows an account timeline.

## Example

An account might have activity like this:

```text
10:01  Failed login
10:01  Failed login
10:01  Failed login
10:01  Successful login
10:03  PowerShell started
10:05  Network connection to port 445
```

Looking at these events together provides more context than looking at each event separately.

The project uses a 10-minute correlation window when connecting related events.

## Detection Logic

The current version checks for:

### Repeated Authentication Failures

Three or more failed logins within the correlation window are flagged.

### Failed Logins Followed By Success

Multiple failed logins followed by a successful authentication are correlated and flagged.

### Authentication + PowerShell

PowerShell activity occurring shortly after suspicious authentication activity is treated as an additional indicator.

### Authentication + Network Activity

Connections to common Windows administration ports such as 445 and 3389 are correlated with recent successful authentication.

### Privileged Accounts

Activity involving accounts configured as privileged receives additional investigation priority.

### Multiple Indicators

When several different indicators are found for the same account, the project increases its risk score.

## Risk Scoring

The current scoring model is:

| Indicator                               | Points |
| --------------------------------------- | -----: |
| Repeated authentication failures        |    +25 |
| Failed logins followed by success       |    +30 |
| PowerShell + authentication correlation |    +25 |
| Administrative network activity         |    +20 |
| Privileged account activity             |    +20 |
| Multiple indicators                     |    +15 |

The score is only a way to prioritize investigation. It does not prove that an account has been compromised.

## Account Timelines

One of the main things I wanted to add to this project was a simple timeline.

Instead of only displaying:

```text
[ALERT] Suspicious activity detected
```

the program shows the events belonging to an account in chronological order.

For example:

```text
10:01:12 | AUTH_FAILED
10:01:18 | AUTH_FAILED
10:01:25 | AUTH_FAILED
10:01:32 | AUTH_SUCCESS
10:03:10 | POWERSHELL -> powershell.exe
10:05:20 | NETWORK_CONNECTION -> 10.0.0.10:445
```

This makes it easier to understand why an alert was generated.

## Project Structure

```text
security-log-correlation-engine/
├── correlation_engine.py
├── security_logs.csv
├── README.md
└── requirements.txt
```

## Running the Project

You only need Python installed.

```bash
python correlation_engine.py
```

The program reads `security_logs.csv` and prints the detected alerts, risk assessment, account timelines, and investigation summary.

## What I Learned

This project helped me practice:

* Python log processing
* Event correlation
* Time-window analysis
* Authentication monitoring
* PowerShell activity analysis
* Network event analysis
* Building security detection rules
* Basic risk scoring
* Creating investigation timelines

The main thing I took from this project is that security events become more useful when they are looked at in context.

## Limitations

This is a learning project using synthetic data.

The detection rules are intentionally simple and are not intended to replace a SIEM or EDR system.

In a real environment, these detections would need more context, including:

* Logon types
* User and device baselines
* Process creation events
* More Windows Event IDs
* Network context
* EDR data
* PowerShell command details
* Asset criticality

## Future Improvements

Some improvements I would like to make:

* Support for real Windows Event Log exports
* More Windows Event IDs
* Better user and device baselines
* JSON log support
* Configurable detection rules
* Exporting investigation reports
* A simple dashboard
* SIEM integration

## Disclaimer

This project is for defensive security learning and uses synthetic security logs.
