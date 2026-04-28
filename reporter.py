def generate_report(findings):
    if not findings:
        print("[+] No vulnerabilities found.")
        return

    with open("report.txt", "w") as report:
        report.write("=" * 50 + "\n")
        report.write("Aegis Vulnerability Scan Report\n")
        report.write("=" * 50 + "\n\n")

        for vuln in findings:
            entry = (
                f"Type   : {vuln['type']}\n"
                f"URL    : {vuln['url']}\n"
                f"Param  : {vuln['param']}\n"
                f"Payload: {vuln['payload']}\n"
                f"Reason : {vuln['reason']}\n"
                + "-" * 50 + "\n"
            )

            print(entry)
            report.write(entry)

    print("[+] Report saved to report.txt")
