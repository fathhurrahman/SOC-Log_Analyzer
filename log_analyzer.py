import re
from collections import Counter
from datetime import datetime


def extract_ip(line):
    """Extract a valid IPv4 address from a log line."""

    match = re.search(
        r"IP:\s*(\d{1,3}(?:\.\d{1,3}){3})",
        line
    )

    if not match:
        return None

    ip = match.group(1)

    # Validate IPv4 octets
    octets = ip.split(".")

    if all(0 <= int(octet) <= 255 for octet in octets):
        return ip

    return None


def analyze_log(file_path):
    """
    Analyze a log file and identify failed login attempts.

    Returns:
        tuple:
            failed_logins - list of failed login log entries
            ip_counts - Counter containing failed attempts per IP
    """

    failed_logins = []
    ip_addresses = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:

            if "Failed login" not in line:
                continue

            cleaned_line = line.strip()
            failed_logins.append(cleaned_line)

            ip = extract_ip(cleaned_line)

            if ip:
                ip_addresses.append(ip)

    ip_counts = Counter(ip_addresses)

    return failed_logins, ip_counts


def get_risk_level(attempts):
    """Classify an IP based on the number of failed login attempts."""

    if attempts >= 5:
        return "HIGH"
    elif attempts >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def get_recommendation(risk):
    """Return a security recommendation based on risk level."""

    recommendations = {
        "HIGH": "Investigate immediately and consider blocking the IP.",
        "MEDIUM": "Investigate the login activity and monitor the IP.",
        "LOW": "Continue monitoring the IP."
    }

    return recommendations.get(
        risk,
        "Review the activity and investigate further."
    )


def generate_report(failed_logins, ip_counts):
    """Generate a professional SOC security report."""

    high_risk = 0
    medium_risk = 0
    low_risk = 0

    with open("security_report.txt", "w", encoding="utf-8") as report:

        report.write("=" * 50 + "\n")
        report.write("             SOC SECURITY REPORT\n")
        report.write("=" * 50 + "\n\n")

        report.write(
            f"Report Generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        report.write(
            f"Total Failed Login Attempts: {len(failed_logins)}\n"
        )

        report.write(
            f"Unique Source IP Addresses: {len(ip_counts)}\n\n"
        )

        report.write("IP RISK ANALYSIS\n")
        report.write("-" * 50 + "\n")

        # Sort IPs by highest number of failed attempts
        sorted_ips = sorted(
            ip_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )

        for ip, count in sorted_ips:

            risk = get_risk_level(count)
            recommendation = get_recommendation(risk)

            if risk == "HIGH":
                high_risk += 1
            elif risk == "MEDIUM":
                medium_risk += 1
            else:
                low_risk += 1

            report.write(
                f"IP Address: {ip}\n"
                f"Failed Attempts: {count}\n"
                f"Risk Level: {risk}\n"
                f"Recommendation: {recommendation}\n"
            )

            report.write("-" * 50 + "\n")

        report.write("\nRISK SUMMARY\n")
        report.write("-" * 50 + "\n")
        report.write(f"HIGH Risk IPs: {high_risk}\n")
        report.write(f"MEDIUM Risk IPs: {medium_risk}\n")
        report.write(f"LOW Risk IPs: {low_risk}\n")

        report.write("\n" + "=" * 50 + "\n")
        report.write("End of SOC Security Report\n")
        report.write("=" * 50 + "\n")


if __name__ == "__main__":

    print("=" * 50)
    print("             SOC LOG ANALYZER")
    print("=" * 50)

    log_file = input("Enter log file path: ").strip()

    try:
        failed_logins, ip_counts = analyze_log(log_file)

        print(f"\nFailed Login Attempts: {len(failed_logins)}")

        print("\nIP Risk Analysis:")
        print("-" * 50)

        sorted_ips = sorted(
            ip_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )

        for ip, count in sorted_ips:

            risk = get_risk_level(count)
            recommendation = get_recommendation(risk)

            print(
                f"{ip} -> "
                f"{count} failed attempts -> "
                f"{risk} RISK"
            )

            print(f"Recommendation: {recommendation}")
            print()

        generate_report(failed_logins, ip_counts)

        print("Security report generated: security_report.txt")

    except FileNotFoundError:
        print("\nError: Log file not found.")
        print("Please check the file path and try again.")

    except PermissionError:
        print("\nError: Permission denied.")
        print("Please check your access to the log file.")

    except ValueError:
        print("\nError: Invalid log data detected.")

    except Exception as error:
        print(f"\nUnexpected error: {error}")