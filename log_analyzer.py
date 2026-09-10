import re
from collections import Counter


def analyze_log(file_path):
    failed_logins = []
    ip_addresses = []

    with open(file_path, "r") as file:
        for line in file:
            if "Failed login" in line:
                failed_logins.append(line.strip())

                match = re.search(
                    r"IP:\s*(\d+\.\d+\.\d+\.\d+)", line
                )

                if match:
                    ip_addresses.append(match.group(1))

    ip_counts = Counter(ip_addresses)

    return failed_logins, ip_counts


def get_risk_level(attempts):
    if attempts >= 5:
        return "HIGH"
    elif attempts >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def get_recommendation(risk):
    if risk == "HIGH":
        return "Investigate immediately and consider blocking the IP."
    elif risk == "MEDIUM":
        return "Investigate the login activity and monitor the IP."
    else:
        return "Continue monitoring the IP."


def generate_report(failed_logins, ip_counts):
    with open("security_report.txt", "w") as report:

        report.write("======================================\n")
        report.write("        SOC SECURITY REPORT\n")
        report.write("======================================\n\n")

        report.write(
            f"Total Failed Login Attempts: {len(failed_logins)}\n\n"
        )

        report.write("IP RISK ANALYSIS\n")
        report.write("----------------\n")

        for ip, count in ip_counts.items():
            risk = get_risk_level(count)
            recommendation = get_recommendation(risk)

            report.write(
                f"{ip} -> {count} failed attempts -> {risk} RISK\n"
            )

            report.write(
                f"Recommendation: {recommendation}\n\n"
            )


if __name__ == "__main__":
    print("======================================")
    print("        SOC LOG ANALYZER")
    print("======================================")

    log_file = input("Enter log file path: ")

    failed_logins, ip_counts = analyze_log(log_file)

    print("\nFailed Login Attempts:", len(failed_logins))

    print("\nIP Risk Analysis:")

    for ip, count in ip_counts.items():
        risk = get_risk_level(count)
        recommendation = get_recommendation(risk)

        print(
            f"{ip} -> {count} failed attempts -> {risk} RISK"
        )

        print(f"Recommendation: {recommendation}")

    generate_report(failed_logins, ip_counts)

    print("\nSecurity report generated: security_report.txt")