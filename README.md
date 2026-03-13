# 🛡️ CIS Microsoft Intune for Windows 11 Benchmark v4.0.0 Level 1 (L1) Assessment Script

<div align="center">

[![GitHub stars](https://img.shields.io/github/stars/nakotw/CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1?style=for-the-badge)](https://github.com/nakotw/CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/nakotw/CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1?style=for-the-badge)](https://github.com/nakotw/CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1/network)
[![GitHub issues](https://img.shields.io/github/issues/nakotw/CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1?style=for-the-badge)](https://github.com/nakotw/CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1/issues)

**Automated PowerShell script for assessing Windows 11 configurations against the CIS Microsoft Intune Benchmark v4.0.0 Level 1.**

</div>

## 📖 Overview

This repository provides a standalone PowerShell script designed to automate the assessment of Windows 11 endpoints against the security recommendations outlined in the **CIS Microsoft Intune for Windows 11 Benchmark v4.0.0 Level 1 (L1)**.

The script helps organizations quickly identify configurations that deviate from the CIS L1 recommendations, ensuring a higher security posture for Windows 11 devices managed through Microsoft Intune. It's an essential tool for compliance, auditing, and maintaining secure configurations in enterprise environments.

## ✨ Features

-   **Automated Assessment:** Programmatically checks numerous Windows 11 security settings against CIS Benchmark v4.0.0 L1.
-   **Intune-Specific Focus:** Tailored for configurations typically managed or influenced by Microsoft Intune policies.
-   **Detailed Reporting:** (Inferred) Provides output indicating compliance status for each audited control, helping pinpoint non-compliant areas.
-   **Security Hardening Aid:** Assists in validating the effectiveness of security policies and identifying gaps for further hardening.
-   **PowerShell Native:** Written in PowerShell for broad compatibility with Windows environments.

## 🛠️ Tech Stack

-   **Scripting Language:** ![PowerShell](https://img.shields.io/badge/PowerShell-01213D?style=for-the-badge&logo=powershell&logoColor=white)
-   **Target OS:** ![Windows 11](https://img.shields.io/badge/Windows%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white)
-   **Management Platform (Contextual):** ![Microsoft Intune](https://img.shields.io/badge/Microsoft%20Intune-505050?style=for-the-badge&logo=microsoft&logoColor=white)

## 🚀 Quick Start

### Prerequisites
-   A machine running **Windows 11**.
-   **PowerShell 5.1** or newer (built-in with modern Windows versions).
-   **Administrative privileges** are required to run the script effectively, as it queries system-level security settings.

### Installation

1.  **Clone the repository** (or download the script directly):
    ```bash
    git clone https://github.com/nakotw/CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1.git
    cd CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1
    ```

### Usage

1.  **Open PowerShell as Administrator:**
    *   Right-click on the PowerShell icon (or search for "PowerShell") and select "Run as Administrator."

2.  **Navigate to the script directory:**
    ```powershell
    Set-Location -Path "C:\path\to\your\cloned\repo" # Adjust path accordingly
    ```

3.  **Ensure PowerShell Execution Policy allows script execution:**
    If you encounter an error like "cannot be loaded because running scripts is disabled on this system," you may need to adjust your execution policy.
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    ```
    *(Note: You can revert this policy after running the script if desired: `Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force`)*

4.  **Execute the assessment script:**
    ```powershell
    .\CIS_Intune_W11_v4_Full_Local_Audit_fixed_v4.ps1 -AuditFilePath .\CIS_Microsoft_Intune_for_Windows_11_v4.0.0_L1.audit `-OutputDirectory "C:\Temp\CIS_Intune_W11_v4_Audit"
    ```
    The script will run through the checks and display the assessment results in the console.

## 📁 Project Structure

```
CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1/
├── CIS_Intune_W11_v4_Assessment.ps1 # The main PowerShell assessment script
├── CIS_Microsoft_Intune_for_Windows_11_v4.0.0_L1.audit # The audit file
└── README.md                         # This README file
```

## 📜 CIS Benchmark Details

This script specifically targets the recommendations found in the **CIS Microsoft Intune for Windows 11 Benchmark v4.0.0 Level 1 (L1)**. The Center for Internet Security (CIS) Benchmarks are a globally recognized set of best practices for securely configuring systems. Level 1 recommendations are generally considered to be essential security configurations that are straightforward to implement and won't inhibit the utility of the technology.

For detailed information on the benchmark, please refer to the official CIS documentation.

## 🤝 Contributing

We welcome contributions to improve this assessment script! If you find issues, have suggestions for enhancements, or want to add more checks, please feel free to:

1.  **Fork the repository.**
2.  **Create a new branch** for your feature or bug fix.
3.  **Commit your changes** with descriptive messages.
4.  **Push your branch** to your fork.
5.  **Open a Pull Request** against the `main` branch of this repository.

Please ensure your contributions align with the project's purpose of assessing against the specified CIS Benchmark.

## 🙏 Acknowledgments

-   **Center for Internet Security (CIS):** For providing the industry-standard security benchmarks that this script is based upon.

## 📞 Support & Contact

-   🐛 Issues: [GitHub Issues](https://github.com/nakotw/CIS-Microsoft-Intune-for-Windows-11-v4.0.0-L1/issues)

---

<div align="center">

**⭐ Star this repo if you find it helpful for your security assessments!**

Made with ❤️ by nakotw

</div>
